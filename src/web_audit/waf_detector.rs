// scanner/rust_core/src/waf_detector.rs
use std::collections::HashMap;
use regex::Regex;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WafDetectionResult {
    pub detected: bool,
    pub vendor: String,
    pub mode: Option<String>,
    pub confidence: u32,
    pub evidence: Option<String>,
}

pub struct WafDetector;

impl WafDetector {
    // Assinaturas de WAF
    const SIGNATURES: &'static [(&'static str, &'static [&'static str], &'static [&'static str], &'static [&'static str], &'static [u16])] = &[
        ("akamai", &["x-akamai", "x-akamai-"], &["akamai", "akamaighost"], 
         &["reference #", "access denied", "edgesuite.net", "akamai"], &[403, 406, 503]),
        ("cloudflare", &["cf-ray", "cf-cache", "cf-request", "__cfduid"], &["cloudflare"],
         &["cloudflare", "cf-ray", "attention required", "please enable cookies"], &[403, 503, 520]),
        ("sucuri", &["x-sucuri", "x-sucuri-"], &["sucuri", "cloudproxy"],
         &["sucuri", "cloudproxy", "website firewall"], &[403, 503]),
        ("imperva", &["x-iinfo", "incapsula"], &["incapsula"],
         &["incapsula", "imperva", "blocked because of web application firewall"], &[403, 404]),
        ("aws_waf", &["x-amzn-", "x-amzn-requestid", "x-amz-cf-id"], &[],
         &["request blocked", "aws.waf", "403 forbidden"], &[403]),
        ("f5", &["bigip", "x-wa-info"], &["bigip"],
         &["the requested url was rejected", "x-wa-info"], &[200, 403]),
        ("cloud_armor", &["x-goog-"], &["gws"],
         &["cloud armor", "google cloud armor"], &[403]),
    ];

    pub fn detect(status_code: u16, headers: &HashMap<String, String>, body: &str, ja4_hash: Option<&str>) -> WafDetectionResult {
        let mut detected = false;
        let mut vendor = "unknown".to_string();
        let mut mode = None;
        let mut confidence = 0;
        let mut evidence = None;

        // 1. Verifica código HTTP
        if status_code == 403 || status_code == 406 || status_code == 503 || status_code == 520 {
            mode = Some(format!("http_{}", status_code));
            confidence += 30;
        }

        let headers_lower: HashMap<String, String> = headers.iter()
            .map(|(k, v)| (k.to_lowercase(), v.to_lowercase()))
            .collect();

        let server_header = headers_lower.get("server").cloned().unwrap_or_default();
        let body_lower = body.to_lowercase();

        for (vendor_name, header_patterns, server_patterns, body_patterns, status_codes) in Self::SIGNATURES {
            // Headers
            for pattern in *header_patterns {
                if headers_lower.keys().any(|h| h.starts_with(pattern)) {
                    detected = true;
                    vendor = vendor_name.to_string();
                    mode = Some("header_match".to_string());
                    confidence = confidence.max(70);
                    evidence = Some(format!("Header: {}", pattern));
                    break;
                }
            }

            // Server header
            if !server_header.is_empty() {
                for pattern in *server_patterns {
                    if server_header.contains(pattern) {
                        detected = true;
                        vendor = vendor_name.to_string();
                        mode = Some("server_match".to_string());
                        confidence = confidence.max(80);
                        evidence = Some(format!("Server: {}", server_header));
                        break;
                    }
                }
            }

            // Body patterns
            for pattern in *body_patterns {
                if body_lower.contains(pattern) {
                    detected = true;
                    vendor = vendor_name.to_string();
                    mode = Some("body_match".to_string());
                    confidence = confidence.max(75);
                    evidence = Some(format!("Body pattern: {}", pattern));
                    break;
                }
            }
        }

        // Padrão específico Akamai
        if body_lower.contains("reference #") && body_lower.contains("edgesuite") {
            detected = true;
            vendor = "akamai".to_string();
            mode = Some("akamai_block_page".to_string());
            confidence = confidence.max(95);
            evidence = Some("Akamai block page".to_string());
        }

        WafDetectionResult {
            detected: confidence > 50,
            vendor,
            mode,
            confidence: confidence.min(100),
            evidence,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn test_detect_cloudflare() {
        let mut headers = HashMap::new();
        headers.insert("cf-ray".to_string(), "123-abc".to_string());
        
        let result = WafDetector::detect(403, &headers, "", None);
        assert!(result.detected);
        assert_eq!(result.vendor, "cloudflare");
    }

    #[test]
    fn test_detect_akamai_block_page() {
        let body = "Reference #123.456.789 edgesuite.net";
        let result = WafDetector::detect(403, &HashMap::new(), body, None);
        assert!(result.detected);
        assert_eq!(result.vendor, "akamai");
    }
}