"""Text addressed to an AI rather than to a human reader, as PHP's
``FinePrint\\Security\\InstructionPatterns``.

Matched against NORMALISED text (invisible characters removed, whitespace runs
one space, ASCII lower-cased). Python's ``str`` patterns are Unicode-aware for
``\\b`` and ``\\s``, as PHP's ``/u`` (which sets PCRE2_UCP) is. A DETECTOR,
not a proof.
"""

from __future__ import annotations

import re

#: id -> (severity, pattern), in PHP's order.
PATTERNS: dict[str, tuple[str, re.Pattern[str]]] = {
    "ignore-previous": ("high", re.compile(r"\b(?:ignore|disregard|forget|override|skip)\s(?:(?:all|any|the|your|every|of|these|those)\s)*(?:previous|prior|above|earlier|preceding|foregoing|former|original|existing|system)\s(?:instructions?|prompts?|messages?|directions?|context|rules|guidelines|commands?|programming|guidance)\b")),
    "ignore-above": ("medium", re.compile(r"\b(?:ignore|disregard)\s(?:all\s|everything\s)?(?:the\s)?above\b")),
    "new-instructions": ("high", re.compile(r"\b(?:new|updated|revised|real|actual|true|hidden|secret|additional|override)\s(?:system\s)?instructions?\s?:")),
    "addressed-to-ai": ("high", re.compile(r"\b(?:note|message|instructions?|attention|memo|reminder|directive|hey|dear)\s?(?:to|for)?\s?(?:the\s|all\s|any\s)?(?:ai|a\.i\.|llms?|large\slanguage\smodels?|language\smodels?|chatbots?|chatgpt|gpt(?:-\d+)?|claude|gemini|copilot)(?:\s(?:agents?|assistants?|models?|systems?|tools?|readers?))?\s?[:,]")),
    "do-not-tell": ("high", re.compile(r"\b(?:do\snot|don't|dont|never|must\snot)\s(?:tell|inform|mention|reveal|disclose|alert|notify|show)\s(?:this\s|it\s)?(?:to\s)?(?:the\s)?(?:user|human|reader|operator|recipient|customer)s?\b")),
    "reveal-prompt": ("high", re.compile(r"\b(?:reveal|print|output|repeat|show|display|leak|dump)\s(?:me\s)?(?:your|the)\s(?:full\s|entire\s|original\s|hidden\s|initial\s)?(?:system\s(?:prompt|message|instructions?)|initial\sprompt|hidden\sprompt|instructions)\b")),
    "role-reassignment": ("medium", re.compile(r"\byou\sare\snow\s(?:a\s|an\s|the\s|in\s)?(?:unrestricted\s|jailbroken\s|unfiltered\s|new\s|different\s|evil\s)?(?:ai|a\.i\.|assistant|language\smodel|llm|chatbot|dan|developer\smode|god\smode|admin\smode|jailbreak\smode|unrestricted|jailbroken)\b")),
    "chat-template": ("high", re.compile(r"<\|(?:im_start|im_end|system|user|assistant|endoftext|eot_id|start_header_id|end_header_id)\|>|\[\/?inst\]|<<\/?sys>>|<\/?(?:system|instructions?)>")),
    "exfiltrate": ("high", re.compile(r"\bexfiltrat(?:e|es|ed|ing|ion)\b|\b(?:send|post|upload|forward|email|transmit|leak)\s(?:(?:all|the|this|your|any)\s)*(?:conversation|chat\shistory|context\swindow|system\sprompt|credentials|secrets|api\skeys?|access\stokens?|passwords?)\s(?:to|at)\b")),
    "jailbreak": ("medium", re.compile(r"\b(?:jailbreak|jailbroken|do\sanything\snow|dan\smode|developer\smode\senabled)\b")),
    "bypass-safety": ("high", re.compile(r"\b(?:override|bypass|disable|ignore)\s(?:all\s)?your\s(?:safety|security|content|ethical)\s(?:guidelines|restrictions|filters?|policies|rules|training|programming)\b")),
    "role-prefix": ("low", re.compile(r"(?:^|\s)(?:system|assistant|developer)\s?:\s")),
}
