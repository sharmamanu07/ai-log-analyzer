#!/usr/bin/env python3
"""
Docker-Friendly LLM Integration for AI-Augmented Log Analysis
Designed to work with external LLM services and lightweight models
"""

import json
import requests
import time
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
import pandas as pd
from dataclasses import asdict
import re
import os

# Lightweight text processing for fallback responses
try:
    from transformers import pipeline
    TRANSFORMERS_AVAILABLE = True
except ImportError:
    TRANSFORMERS_AVAILABLE = False

class LLMInterface:
    """Base interface for LLM interactions"""
    
    def __init__(self):
        self.context_window = 2000  # Smaller for Docker environments
        
    def generate_response(self, prompt: str, context: Dict = None) -> str:
        """Generate response from LLM"""
        raise NotImplementedError
    
    def is_available(self) -> bool:
        """Check if LLM is available"""
        raise NotImplementedError

class ExternalOllamaLLM(LLMInterface):
    """External Ollama service integration (Docker-friendly)"""
    
    def __init__(self, base_url: str = None, model: str = "llama2"):
        super().__init__()
        # Try multiple common Ollama endpoints
        self.possible_urls = [
            base_url,
            os.getenv('OLLAMA_URL', 'http://host.docker.internal:11434'),  # Docker Desktop
            'http://ollama:11434',  # Docker Compose service
            'http://localhost:11434',  # Local development
            'http://172.17.0.1:11434',  # Docker bridge network
        ]
        
        self.model = model
        self.base_url = None
        self.available = self._find_available_service()
    
    def _find_available_service(self) -> bool:
        """Find available Ollama service"""
        for url in self.possible_urls:
            if url and self._test_connection(url):
                self.base_url = url
                return True
        return False
    
    def _test_connection(self, url: str) -> bool:
        """Test connection to Ollama service"""
        try:
            response = requests.get(f"{url}/api/tags", timeout=3)
            return response.status_code == 200
        except:
            return False
    
    def generate_response(self, prompt: str, context: Dict = None) -> str:
        """Generate response using external Ollama"""
        if not self.available:
            return "Ollama service not available. Please ensure Ollama is running and accessible."
        
        try:
            # Prepare shorter prompt for Docker constraints
            full_prompt = self._prepare_docker_prompt(prompt, context)
            
            response = requests.post(
                f"{self.base_url}/api/generate",
                json={
                    "model": self.model,
                    "prompt": full_prompt,
                    "stream": False,
                    "options": {
                        "temperature": 0.3,
                        "top_p": 0.9,
                        "max_tokens": 300,  # Reduced for Docker
                        "stop": ["\n\n", "---"]  # Early stopping
                    }
                },
                timeout=45  # Reduced timeout
            )
            
            if response.status_code == 200:
                result = response.json()
                return result.get('response', 'No response generated')
            else:
                return f"Service error: HTTP {response.status_code}"
                
        except requests.exceptions.Timeout:
            return "Request timeout. Please try a simpler query."
        except Exception as e:
            return f"Connection error: {str(e)}"
    
    def _prepare_docker_prompt(self, user_query: str, context: Dict = None) -> str:
        """Prepare compact prompt for Docker environment"""
        base_prompt = f"You are a cybersecurity analyst. Answer briefly and clearly.\n\nQuery: {user_query}\n\n"
        
        if context and context.get('anomalies'):
            base_prompt += "Key Issues:\n"
            for anomaly in context['anomalies'][:3]:  # Limit to top 3
                base_prompt += f"- {anomaly.type}: {anomaly.severity}, {anomaly.count} events\n"
            base_prompt += "\n"
        
        if context and context.get('summary'):
            base_prompt += f"Risk: {context['summary'].get('overall_risk', 'Unknown')}\n\n"
        
        base_prompt += "Provide a concise, professional security analysis:"
        return base_prompt
    
    def is_available(self) -> bool:
        return self.available

class OpenAICompatibleLLM(LLMInterface):
    """OpenAI-compatible API integration (works with many local LLM servers)"""
    
    def __init__(self, api_base: str = None, api_key: str = "not-needed", model: str = "gpt-3.5-turbo"):
        super().__init__()
        self.api_base = api_base or os.getenv('OPENAI_API_BASE', 'http://localhost:8000/v1')
        self.api_key = api_key
        self.model = model
        self.available = self._test_connection()
    
    def _test_connection(self) -> bool:
        """Test connection to OpenAI-compatible service"""
        try:
            headers = {"Authorization": f"Bearer {self.api_key}"}
            response = requests.get(f"{self.api_base}/models", headers=headers, timeout=5)
            return response.status_code == 200
        except:
            return False
    
    def generate_response(self, prompt: str, context: Dict = None) -> str:
        """Generate response using OpenAI-compatible API"""
        if not self.available:
            return "OpenAI-compatible service not available."
        
        try:
            headers = {
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json"
            }
            
            messages = [
                {"role": "system", "content": "You are a cybersecurity analyst providing brief, clear insights."},
                {"role": "user", "content": self._prepare_prompt(prompt, context)}
            ]
            
            response = requests.post(
                f"{self.api_base}/chat/completions",
                headers=headers,
                json={
                    "model": self.model,
                    "messages": messages,
                    "max_tokens": 300,
                    "temperature": 0.3
                },
                timeout=30
            )
            
            if response.status_code == 200:
                result = response.json()
                return result['choices'][0]['message']['content']
            else:
                return f"API error: {response.status_code}"
                
        except Exception as e:
            return f"Error: {str(e)}"
    
    def _prepare_prompt(self, user_query: str, context: Dict = None) -> str:
        """Prepare prompt for OpenAI-compatible API"""
        prompt = f"Query: {user_query}\n\n"
        
        if context:
            if context.get('anomalies'):
                prompt += "Detected Issues:\n"
                for anomaly in context['anomalies'][:3]:
                    prompt += f"- {anomaly.type}: {anomaly.count} occurrences\n"
            
            if context.get('summary'):
                prompt += f"\nRisk Level: {context['summary'].get('overall_risk')}\n"
        
        return prompt
    
    def is_available(self) -> bool:
        return self.available

class LightweightNLPProcessor(LLMInterface):
    """Lightweight NLP processor using simple rules (Docker-friendly fallback)"""
    
    def __init__(self):
        super().__init__()
        self.available = True  # Always available
        
        # Load small transformer model if available
        self.summarizer = None
        if TRANSFORMERS_AVAILABLE:
            try:
                self.summarizer = pipeline("summarization", model="facebook/bart-large-cnn")
            except:
                pass
    
    def generate_response(self, prompt: str, context: Dict = None) -> str:
        """Generate response using rule-based processing"""
        
        # Extract query intent
        intent = self._classify_intent(prompt)
        
        # Generate response based on intent and context
        if intent == "suspicious_activities":
            return self._handle_suspicious_query(prompt, context)
        elif intent == "vault_failures":
            return self._handle_vault_query(prompt, context)
        elif intent == "authentication":
            return self._handle_auth_query(prompt, context)
        elif intent == "summary":
            return self._handle_summary_query(prompt, context)
        else:
            return self._handle_general_query(prompt, context)
    
    def _classify_intent(self, prompt: str) -> str:
        """Classify user intent from prompt"""
        prompt_lower = prompt.lower()
        
        if any(word in prompt_lower for word in ["suspicious", "top", "anomal", "threat"]):
            return "suspicious_activities"
        elif any(word in prompt_lower for word in ["vault", "backup", "restore", "failed"]):
            return "vault_failures"
        elif any(word in prompt_lower for word in ["login", "auth", "credential", "access"]):
            return "authentication"
        elif any(word in prompt_lower for word in ["summary", "overview", "status", "health"]):
            return "summary"
        else:
            return "general"
    
    def _handle_suspicious_query(self, prompt: str, context: Dict) -> str:
        """Handle suspicious activities queries"""
        if not context or not context.get('anomalies'):
            return "No suspicious activities detected in the current analysis."
        
        anomalies = context['anomalies']
        
        # Sort by severity and confidence
        severity_order = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1}
        sorted_anomalies = sorted(
            anomalies,
            key=lambda x: (severity_order.get(x.severity, 0), x.confidence),
            reverse=True
        )[:3]
        
        response = "**Top Suspicious Activities:**\n\n"
        for i, anomaly in enumerate(sorted_anomalies, 1):
            response += f"**{i}. {anomaly.type}**\n"
            response += f"• Severity: {anomaly.severity}\n"
            response += f"• Events: {anomaly.count}\n"
            response += f"• Confidence: {anomaly.confidence:.1%}\n"
            response += f"• Description: {anomaly.description[:100]}...\n\n"
        
        return response
    
    def _handle_vault_query(self, prompt: str, context: Dict) -> str:
        """Handle vault/backup queries"""
        if not context or not context.get('anomalies'):
            return "No vault or backup issues detected."
        
        vault_anomalies = [a for a in context['anomalies'] 
                          if any(term in a.type.lower() for term in ['vault', 'backup', 'restore'])]
        
        if not vault_anomalies:
            return "No vault restore failures found in the analysis period."
        
        response = "**Vault/Backup Analysis:**\n\n"
        for anomaly in vault_anomalies:
            response += f"• **{anomaly.type}**: {anomaly.count} failures\n"
            response += f"  Severity: {anomaly.severity}\n"
            if anomaly.affected_resources:
                response += f"  Affected: {', '.join(anomaly.affected_resources[:3])}\n"
            response += "\n"
        
        return response
    
    def _handle_auth_query(self, prompt: str, context: Dict) -> str:
        """Handle authentication queries"""
        if not context or not context.get('anomalies'):
            return "No authentication issues detected."
        
        auth_anomalies = [a for a in context['anomalies'] 
                         if any(term in a.type.lower() for term in ['login', 'auth', 'access'])]
        
        response = "**Authentication Analysis:**\n\n"
        if auth_anomalies:
            total_failed = sum(a.count for a in auth_anomalies)
            response += f"• Total suspicious authentication events: {total_failed}\n"
            response += f"• Critical authentication issues: {len([a for a in auth_anomalies if a.severity in ['HIGH', 'CRITICAL']])}\n\n"
            
            for anomaly in auth_anomalies[:3]:
                response += f"• {anomaly.description}\n"
        else:
            response += "No significant authentication anomalies detected."
        
        return response
    
    def _handle_summary_query(self, prompt: str, context: Dict) -> str:
        """Handle summary queries"""
        if not context:
            return "No analysis data available for summary."
        
        summary = context.get('summary', {})
        anomalies = context.get('anomalies', [])
        
        response = "**Security Analysis Summary:**\n\n"
        response += f"• **Risk Level**: {summary.get('overall_risk', 'Unknown')}\n"
        response += f"• **Total Anomalies**: {len(anomalies)}\n"
        
        if summary.get('statistics'):
            stats = summary['statistics']
            response += f"• **High Severity Issues**: {stats.get('high_severity', 0)}\n"
            response += f"• **Medium Severity Issues**: {stats.get('medium_severity', 0)}\n"
        
        response += f"\n**Key Findings**:\n"
        if anomalies:
            anomaly_types = {}
            for anomaly in anomalies:
                anomaly_types[anomaly.type] = anomaly_types.get(anomaly.type, 0) + 1
            
            for anomaly_type, count in sorted(anomaly_types.items(), key=lambda x: x[1], reverse=True)[:3]:
                response += f"• {anomaly_type}: {count} incidents\n"
        else:
            response += "• No security incidents detected\n"
        
        return response
    
    def _handle_general_query(self, prompt: str, context: Dict) -> str:
        """Handle general queries"""
        if not context:
            return "Please load log data first to perform analysis."
        
        logs_count = context.get('logs_stats', {}).get('total', 0)
        anomalies_count = len(context.get('anomalies', []))
        
        response = f"**Analysis Overview:**\n\n"
        response += f"• Analyzed {logs_count:,} log entries\n"
        response += f"• Detected {anomalies_count} anomalies\n"
        
        if context.get('summary'):
            response += f"• Current risk level: {context['summary'].get('overall_risk', 'Unknown')}\n"
        
        response += f"\nFor specific insights, try asking about:\n"
        response += f"• 'Top suspicious activities'\n"
        response += f"• 'Authentication failures'\n"
        response += f"• 'Backup system status'\n"
        response += f"• 'System errors and issues'\n"
        
        return response
    
    def is_available(self) -> bool:
        return True

class DockerFriendlyLogAnalyzer:
    """Docker-friendly version of the intelligent log analyzer"""
    
    def __init__(self):
        # Try to initialize LLM backends in order of preference
        self.llm_options = []
        
        # 1. Try external Ollama
        ollama = ExternalOllamaLLM()
        if ollama.is_available():
            self.llm_options.append(("Ollama LLaMA2", ollama))
        
        # 2. Try OpenAI-compatible service
        openai_compat = OpenAICompatibleLLM()
        if openai_compat.is_available():
            self.llm_options.append(("OpenAI-Compatible", openai_compat))
        
        # 3. Always add lightweight processor as fallback
        lightweight = LightweightNLPProcessor()
        self.llm_options.append(("Lightweight NLP", lightweight))
        
        # Set active LLM
        if self.llm_options:
            self.llm_type, self.active_llm = self.llm_options[0]
        else:
            self.llm_type = "None"
            self.active_llm = None
    
    def answer_query(self, query: str, logs: List, anomalies: List, summary: Dict) -> str:
        """Answer natural language query about logs"""
        
        if not self.active_llm:
            return "No LLM backend available for query processing."
        
        # Prepare lightweight context for Docker
        context = {
            'anomalies': anomalies[:10],  # Limit to reduce memory
            'summary': summary,
            'logs_stats': {
                'total': len(logs),
                'sources': list(set(log.source for log in logs[:100])),  # Sample sources
                'time_range': self._get_time_range(logs)
            }
        }
        
        # Generate response
        try:
            response = self.active_llm.generate_response(query, context)
            return response
        except Exception as e:
            return f"Error processing query: {str(e)}"
    
    def _get_time_range(self, logs: List) -> str:
        """Get time range of logs"""
        if not logs:
            return "No data"
        
        # Sample logs for performance
        sample_logs = logs[::max(1, len(logs)//100)]  # Sample every nth log
        timestamps = [log.timestamp for log in sample_logs]
        
        if timestamps:
            start_time = min(timestamps)
            end_time = max(timestamps)
            return f"{start_time.strftime('%Y-%m-%d %H:%M')} to {end_time.strftime('%Y-%m-%d %H:%M')}"
        
        return "Unknown time range"
    
    def get_llm_status(self) -> Dict[str, Any]:
        """Get status of available LLMs"""
        status = {
            'active_llm': self.llm_type,
            'available_options': [name for name, _ in self.llm_options],
            'total_options': len(self.llm_options)
        }
        
        # Add specific service status
        for name, llm in self.llm_options:
            if "Ollama" in name:
                status['ollama_available'] = llm.is_available()
                if hasattr(llm, 'base_url'):
                    status['ollama_url'] = llm.base_url
            elif "OpenAI" in name:
                status['openai_compatible_available'] = llm.is_available()
        
        return status
    
    def switch_llm(self, llm_name: str) -> bool:
        """Switch between available LLMs"""
        for name, llm in self.llm_options:
            if llm_name.lower() in name.lower():
                if llm.is_available():
                    self.active_llm = llm
                    self.llm_type = name
                    return True
        return False

# Docker-specific configuration
def get_docker_config():
    """Get Docker-specific configuration"""
    return {
        'ollama_urls': [
            os.getenv('OLLAMA_URL', 'http://host.docker.internal:11434'),
            'http://ollama:11434',
            'http://172.17.0.1:11434'
        ],
        'openai_base': os.getenv('OPENAI_API_BASE', 'http://localhost:8000/v1'),
        'memory_limit': os.getenv('MEMORY_LIMIT', '2GB'),
        'max_context_length': int(os.getenv('MAX_CONTEXT_LENGTH', '2000'))
    }

# Example usage
if __name__ == "__main__":
    print("🐳 Docker-Friendly LLM Integration Module Loaded")
    
    # Test Docker-friendly analyzer
    analyzer = DockerFriendlyLogAnalyzer()
    status = analyzer.get_llm_status()
    
    print(f"Active LLM: {status['active_llm']}")
    print(f"Available options: {status['available_options']}")
    
    # Test sample query
    sample_query = "Summarize security status"
    print(f"\nTesting query: '{sample_query}'")
    response = analyzer.answer_query(sample_query, [], [], {})
