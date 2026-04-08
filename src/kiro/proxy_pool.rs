//! 代理池模块
//!
//! 从外部接口按需获取代理，支持：
//! - 启动时为每个凭据分配独立代理
//! - 代理故障时自动从接口获取新代理（不复用已故障代理）
//! - 后台定期健康检测（TCP 连接探测）

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use serde::Deserialize;
use tokio::sync::Mutex as TokioMutex;

use crate::http_client::ProxyConfig;

/// 代理池 API 响应外层结构
#[derive(Debug, Clone, Deserialize)]
struct ProxyApiResponse {
    success: bool,
    data: Option<Vec<ProxyApiItem>>,
    error: Option<String>,
}

/// 代理池 API 响应 data 数组中的单条代理
#[derive(Debug, Clone, Deserialize)]
struct ProxyApiItem {
    /// 完整代理地址，如"http://123.45.67.89:8080"
    proxy: String,
}

/// 代理条目内部状态
#[derive(Debug, Clone)]
struct ProxyEntry {
    config: ProxyConfig,
    /// 是否已被标记为故障
    failed: bool,
    /// 最后一次故障时间
    failed_at: Option<Instant>,
    /// 分配给哪个凭据 ID（None 表示未分配）
    assigned_to: Option<u64>,
}

/// 代理池
///
/// 线程安全，可在 MultiTokenManager 中以 Arc 共享
pub struct ProxyPool {
    /// 代理池 API 地址
    api_url: String,
    /// 当前所有代理（包括已故障的）
    entries: Mutex<Vec<ProxyEntry>>,
    /// 已知故障代理 URL 集合（用于去重，避免接口返回重复故障代理）
    failed_urls: Mutex<HashSet<String>>,
    /// TLS 后端（用于健康检测时构建 client）
    tls_backend: crate::model::config::TlsBackend,
    /// per-credential 异步分配锁，消除 assign_proxy_for 的 TOCTOU 竞态
    assign_locks: Mutex<HashMap<u64, Arc<TokioMutex<()>>>>,
}

impl ProxyPool {
    /// 创建代理池
    pub fn new(api_url: impl Into<String>, tls_backend: crate::model::config::TlsBackend) -> Self {
        Self {
            api_url: api_url.into(),
            entries: Mutex::new(Vec::new()),
            failed_urls: Mutex::new(HashSet::new()),
            tls_backend,
            assign_locks: Mutex::new(HashMap::new()),
        }
    }

    /// 从接口获取一个新代理（异步）
    ///
    /// 若接口返回的代理已在故障列表中，则重试最多 3 次
    pub async fn fetch_new_proxy(&self) -> anyhow::Result<ProxyConfig> {
        let failed_urls = self.failed_urls.lock().clone();

        for attempt in 0..3u32 {
            let proxy_config = self.call_proxy_api().await?;

            if !failed_urls.contains(&proxy_config.url) {
                return Ok(proxy_config);
            }

            tracing::debug!(
                "代理接口返回了已故障的代理 {}，重试（{}/3）",
                proxy_config.url,
                attempt + 1
            );
        }

        // 3 次重试后仍拿到故障代理，直接返回（接口侧可能没有更多可用代理）
        self.call_proxy_api().await
    }

    /// 为指定凭据分配一个代理
    ///
    /// 优先复用已分配给该凭据的代理（若未故障）；
    /// 否则从接口获取新代理并记录分配关系。
    ///
    /// 使用 per-credential 异步锁，消除并发调用时重复获取代理的 TOCTOU 竞态。
    pub async fn assign_proxy_for(&self, credential_id: u64) -> anyhow::Result<ProxyConfig> {
        // 快速路径：无锁前置检查，已有可用代理直接返回
        {
            let entries = self.entries.lock();
            if let Some(entry) = entries
                .iter()
                .find(|e| e.assigned_to == Some(credential_id) && !e.failed)
            {
                return Ok(entry.config.clone());
            }
        }

        // 获取（或创建）该凭据的分配锁，序列化同一凭据的并发分配请求
        let lock = {
            let mut locks = self.assign_locks.lock();
            Arc::clone(locks.entry(credential_id).or_insert_with(|| Arc::new(TokioMutex::new(()))))
        };
        let _guard = lock.lock().await;

        // 持锁后二次检查：前一个并发请求可能已完成分配
        {
            let entries = self.entries.lock();
            if let Some(entry) = entries
                .iter()
                .find(|e| e.assigned_to == Some(credential_id) && !e.failed)
            {
                return Ok(entry.config.clone());
            }
        }

        // 确认无可用代理，从接口获取新代理
        let proxy = self.fetch_new_proxy().await?;

        {
            let mut entries = self.entries.lock();
            // 移除该凭据旧的故障代理记录
            entries.retain(|e| e.assigned_to != Some(credential_id) || !e.failed);
            // 添加新代理
            entries.push(ProxyEntry {
                config: proxy.clone(),
                failed: false,
                failed_at: None,
                assigned_to: Some(credential_id),
            });
        }

        tracing::info!(
            "凭据 #{} 分配新代理: {}",
            credential_id,
            proxy.url
        );
        Ok(proxy)
    }

    /// 标记指定凭据的代理为故障
    ///
    /// 将该代理加入故障集合，下次 assign_proxy_for 时会从接口获取新代理
    pub fn mark_proxy_failed(&self, credential_id: u64) {
        let failed_url = {
            let mut entries = self.entries.lock();
            let entry = entries
                .iter_mut()
                .find(|e| e.assigned_to == Some(credential_id) && !e.failed);
            if let Some(e) = entry {
                e.failed = true;
                e.failed_at = Some(Instant::now());
                tracing::warn!("凭据 #{} 的代理 {} 已标记为故障", credential_id, e.config.url);
                Some(e.config.url.clone())
            } else {
                None
            }
        };

        if let Some(url) = failed_url {
            self.failed_urls.lock().insert(url);
        }
    }

    /// 获取指定凭据当前分配的代理（若存在且未故障）
    pub fn get_proxy_for(&self, credential_id: u64) -> Option<ProxyConfig> {
        let entries = self.entries.lock();
        entries
            .iter()
            .find(|e| e.assigned_to == Some(credential_id) && !e.failed)
            .map(|e| e.config.clone())
    }

    /// 后台健康检测：对所有已分配且未故障的代理发起 TCP 探测
    ///
    /// 建议通过 tokio::spawn 定期调用（如每 60 秒）
    pub async fn health_check_all(&self) {
        let to_check: Vec<(u64, ProxyConfig)> = {
            let entries = self.entries.lock();
            entries
                .iter()
                .filter(|e| !e.failed && e.assigned_to.is_some())
                .map(|e| (e.assigned_to.unwrap(), e.config.clone()))
                .collect()
        };

        // 并行探测所有代理，不再串行等待每个 TCP 连接
        let futs = to_check.iter().map(|(credential_id, proxy)| async move {
            let alive = self.check_proxy_alive(proxy).await;
            (*credential_id, alive)
        });
        let results = futures::future::join_all(futs).await;

        for (credential_id, alive) in results {
            if !alive {
                // 找到对应 url 用于日志
                let url = {
                    let entries = self.entries.lock();
                    entries
                        .iter()
                        .find(|e| e.assigned_to == Some(credential_id) && !e.failed)
                        .map(|e| e.config.url.clone())
                        .unwrap_or_default()
                };
                tracing::warn!(
                    "健康检测：凭据 #{} 的代理 {} 不可达，标记为故障",
                    credential_id,
                    url
                );
                self.mark_proxy_failed(credential_id);
            }
        }
    }

    /// 检测代理是否存活（通过 HTTP HEAD 请求探测）
    async fn check_proxy_alive(&self, proxy: &ProxyConfig) -> bool {
        use crate::http_client::build_client;

        let client = match build_client(Some(proxy), 10, self.tls_backend) {
            Ok(c) => c,
            Err(_) => return false,
        };

        // 通过代理访问一个轻量级端点探测连通性
        // 使用 AWS 的 connectivity check 端点（与实际 API 同域）
        let result = client
            .get("http://connectivitycheck.gstatic.com/generate_204")
            .timeout(Duration::from_secs(8))
            .send()
            .await;

        match result {
            Ok(resp) => resp.status().as_u16() == 204 || resp.status().is_success(),
            Err(_) => false,
        }
    }

    /// 调用代理 API 批量获取代理
    async fn call_proxy_api_batch(&self, count: usize) -> anyhow::Result<Vec<ProxyConfig>> {
        let url = if self.api_url.contains('?') {
            format!("{}&count={}", self.api_url, count)
        } else {
            format!("{}?count={}", self.api_url, count)
        };
        let resp = reqwest::get(&url)
            .await
            .map_err(|e| anyhow::anyhow!("调用代理 API 失败: {}", e))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("代理 API 返回错误: {} {}", status, body);
        }

        let resp_data: ProxyApiResponse = resp
            .json()
            .await
            .map_err(|e| anyhow::anyhow!("解析代理 API 响应失败: {}", e))?;

        if !resp_data.success {
            let reason = resp_data.error.as_deref().unwrap_or("未知原因");
            anyhow::bail!("代理 API 无可用代理: {}", reason);
        }

        let items = resp_data
            .data
            .ok_or_else(|| anyhow::anyhow!("代理 API 响应缺少 data 字段"))?;

        Ok(items.into_iter().map(|item| ProxyConfig::new(item.proxy)).collect())
    }

    /// 调用代理 API 获取一个代理
    async fn call_proxy_api(&self) -> anyhow::Result<ProxyConfig> {
        let proxies = self.call_proxy_api_batch(1).await?;
        proxies.into_iter().next()
            .ok_or_else(|| anyhow::anyhow!("代理 API 返回空列表"))
    }

    /// 批量为多个凭据分配代理（启动时一次性调用）
    ///
    /// 一次请求拉取 credential_ids.len() 个代理，逐一分配
    pub async fn assign_proxies_batch(&self, credential_ids: &[u64]) -> anyhow::Result<()> {
        if credential_ids.is_empty() {
            return Ok(());
        }

        let count = credential_ids.len();
        let failed_urls = self.failed_urls.lock().clone();

        tracing::info!("批量拉取 {} 个代理...", count);
        let proxies = self.call_proxy_api_batch(count).await?;

        let mut entries = self.entries.lock();
        let mut proxy_iter = proxies.into_iter();
        for credential_id in credential_ids.iter() {
            // 若该凭据已有未故障代理，跳过
            if entries.iter().any(|e| e.assigned_to == Some(*credential_id) && !e.failed) {
                continue;
            }

            let Some(proxy) = proxy_iter.next() else {
                tracing::warn!("代理 API 返回数量不足，凭据 #{} 无代理分配", credential_id);
                continue;
            };

            if failed_urls.contains(&proxy.url) {
                tracing::warn!("凭据 #{} 分配的代理 {} 在故障列表中，仍使用", credential_id, proxy.url);
            }

            tracing::info!("凭据 #{} 初始代理: {}", credential_id, proxy.url);
            entries.push(ProxyEntry {
                config: proxy,
                failed: false,
                failed_at: None,
                assigned_to: Some(*credential_id),
            });
        }

        Ok(())
    }

    /// 获取代理池统计信息（用于调试）
    pub fn stats(&self) -> ProxyPoolStats {
        let entries = self.entries.lock();
        let total = entries.len();
        let failed = entries.iter().filter(|e| e.failed).count();
        let active = total - failed;
        ProxyPoolStats { total, active, failed }
    }
}

/// 代理池统计
#[derive(Debug, Clone)]
pub struct ProxyPoolStats {
    pub total: usize,
    pub active: usize,
    pub failed: usize,
}
