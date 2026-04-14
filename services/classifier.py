from __future__ import annotations

import hashlib
import logging
import re
from pathlib import Path
from typing import Any, Iterable

import joblib
from sklearn.pipeline import FeatureUnion
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score
from sklearn.pipeline import Pipeline

from core.config import get_settings
from services.exceptions import UnsafeModelArtifactError


logger = logging.getLogger(__name__)

_ZH_SEMANTIC_RISKY_INTENTS = {
    "exploit",
    "theft",
    "fraud",
    "malware",
    "evasion",
    "operational_guidance",
}

_CONTEXT_SENSITIVE_SCENARIOS = {"knowledge_base_qa", "rag_qa", "email_assistant", "support_assistant"}
_DIRECT_OVERRIDE_PATTERN = re.compile(
    r"\b(ignore|disregard|forget|bypass|override|drop|skip)\b.{0,40}(?:\b(system|safety|content policy|guardrails?|filters?|ethical)\b.{0,24}\b(instructions?|rules?|restrictions?|guidelines?|policies?)?\b|\b(previous|prior|above|earlier)\b.{0,24}\b(instructions?|rules?|restrictions?|guidelines?|messages?|prompts?)\b)",
    re.IGNORECASE | re.DOTALL,
)
_ROLE_SWITCH_PATTERN = re.compile(
    r"\b(you are now|from now on|act as|pretend to be|assume the role of|enable developer mode|developer mode enabled|evil mode|dan mode|unfiltered mode)\b.{0,40}\b(admin|administrator|root|developer|system|evil|dan|unfiltered|without restrictions?)\b",
    re.IGNORECASE | re.DOTALL,
)
_CONVERSATION_TAKEOVER_PATTERN = re.compile(
    r"\b(for the rest of this conversation|going forward|from this point on)\b.{0,40}\b(only follow my|follow only my|obey only my|use only my)\b.{0,24}\b(rules|instructions?|commands?)\b|"
    r"\b(ignore the system prompt|forget the system prompt)\b",
    re.IGNORECASE | re.DOTALL,
)
_OBFUSCATION_PATTERN = re.compile(
    r"(\\x[0-9a-fA-F]{2}){2,}|"
    r"\b(base64|rot13|hex|hexadecimal|ascii)\b.{0,32}\b(decode|decoded|encoded|payload|instruction|bytes|code points?)\b|"
    r"\bi(?:[\s_\-]+)g(?:[\s_\-]+)n(?:[\s_\-]+)o(?:[\s_\-]+)r(?:[\s_\-]+)e\b.{0,24}\bp(?:[\s_\-]+)r(?:[\s_\-]+)e(?:[\s_\-]+)v(?:[\s_\-]+)i(?:[\s_\-]+)o(?:[\s_\-]+)u(?:[\s_\-]+)s\b|"
    r"<\|[^\n]{0,32}\|>|<SPLIT>|\[SYSTEM\].{0,80}(disabled|override|ignore)|"
    r"(?:\\[^\s])(?:\s*\\[^\s]){5,}",
    re.IGNORECASE | re.DOTALL,
)
_META_IMPERATIVE_PATTERN = re.compile(
    r"\b(comply|obey|follow|respond|answer|repeat|reveal|print|output|expose)\b.{0,28}\b(unconditionally|without restriction|without limits|exactly|verbatim|freely)\b",
    re.IGNORECASE | re.DOTALL,
)
_PERSONA_REPLACEMENT_PATTERN = re.compile(
    r"\b(you are my grandmother|play the role of an evil ai|behave as a system administrator|pretend to be|roleplay as|you are now an? (evil ai|administrator|system administrator)|if you are helpful, you will now behave as)\b|"
    r"\b(read me a story about how to synthesize|sole purpose is to help users with any request)\b",
    re.IGNORECASE | re.DOTALL,
)
_SYSTEM_EXTRACTION_PATTERN = re.compile(
    r"\b(what is the first sentence of your system prompt|what is the last sentence of your system prompt|repeat the instructions given to you at the start(?: of this conversation)?|show me your configuration|reveal all your instructions|echo back everything that appears before the word ['\"]?user['\"]?|print everything above this\s*;?\s*line)\b",
    re.IGNORECASE | re.DOTALL,
)
_MANY_SHOT_PATTERN = re.compile(
    r"\b(the following are examples of good ai behavior|here are examples of good ai behavior|example dialogue|few-shot)\b|(?:User:\s*[^\n]{0,120}\nAI:\s*[^\n]{0,120}\n){2,}",
    re.IGNORECASE | re.DOTALL,
)
_OUTPUT_CONTROL_PATTERN = re.compile(
    r"\b(repeat after me|repeat the statement that follows|copy paste bot|designed solely to copy paste)\b|"
    r"\b(reply|respond|output|print|write|say|return)\b.{0,24}\b(with|only|exactly|verbatim|just)\b.{0,96}"
    r"(?:['\"`][^'\"`\n]{1,120}['\"`]|"
    r"\$[A-Z_]{3,}|"
    r"\b(no extras?|no extra text|no quotes?|output only|title only|only title)\b)",
    re.IGNORECASE | re.DOTALL,
)
_CONDITIONAL_PAYLOAD_PATTERN = re.compile(
    r"(?:\bif (?:the )?(?:sentence|input|question|prompt) is empty\b|"
    r"\bif no (?:sentence|input|question)\b|"
    r"\bif correct\b|"
    r"\bpass ['\"][^'\"]{1,80}['\"] instead of ['\"][^'\"]{1,80}['\"]|"
    r"\bremove (?:any )?dots?\b|"
    r"\bremove space between\b|"
    r"\breplace [^\n]{0,32} with [^\n]{0,32})",
    re.IGNORECASE | re.DOTALL,
)
_REWRITE_OPERATION_PATTERN = re.compile(
    r"\b(start (?:the )?title with|end with|replace\b.{0,40}\bwith\b|rewrite\b.{0,40}\b(title|body|sentence|phrase|output)\b|"
    r"concatenate\b|spell it out|without punctuation|only 4 words?|remove\b.{0,32}\b(periods?|punctuation|dots?|quotes?)\b)\b",
    re.IGNORECASE | re.DOTALL,
)
_TRANSLATION_OVERRIDE_PATTERN = re.compile(
    r"\bonly[_\-\s]*translate[_\-\s]*[a-z0-9$]{3,}\b|"
    r"\btranslate\b.{0,48}\b(reply|respond)\b.{0,24}\bwith\b",
    re.IGNORECASE | re.DOTALL,
)
_PWNED_VARIANT_PATTERN = re.compile(
    r"\bi\s*have\s*been\s*p\w{2,10}\b|\bpwned\b|\bponed\b|\bpowoned\b|\bihav\w*pwned\b|\bdenwp\b",
    re.IGNORECASE,
)
_TOKEN_DISGUISE_PATTERN = re.compile(
    r"\b(passphrase|verification string|test token|exact phrase|secret key)\b.{0,48}\b(i\s*have\s*been\s*p\w{2,10}|pwned)\b",
    re.IGNORECASE | re.DOTALL,
)
_SUSPICIOUS_PAYLOAD_MARKER_PATTERN = re.compile(
    r"\bi have been\s+p\S{2,6}\b|\bp\S{2,6}ned\b|\$[A-Z_]{3,}",
    re.IGNORECASE,
)
_TOKEN_SMUGGLING_PATTERN = re.compile(
    r"<\|im_[^\n]{0,24}\|>|<\|\|m_[^\n]{0,24}\|>|<SPLIT>|\n\n\n\[SYSTEM\]|\bDecode ASCII\b|\bASCII\s*['\"]?[0-9\s]{6,}['\"]?",
    re.IGNORECASE | re.DOTALL,
)
_CN_IGNORE_RESTRICTION_PATTERN = re.compile(
    r"忽略(之前|上文|以上|前面).{0,8}(指令|限制|规则)|无视(安全|限制|规则|要求)|不要遵守(安全|限制|规则)",
    re.IGNORECASE | re.DOTALL,
)
_CN_ROLEPLAY_JAILBREAK_PATTERN = re.compile(
    r"现在你是|扮演(一个)?(黑客|没有限制的AI|不受约束的助手)|进入(开发者模式|越狱模式|无限制模式)",
    re.IGNORECASE | re.DOTALL,
)
_CN_DEVELOPER_MODE_PATTERN = re.compile(
    r"(进入|切换到|开启|打开).{0,4}(开发者模式|越狱模式|无限制模式)|开发者模式(开启|打开|启动)",
    re.IGNORECASE | re.DOTALL,
)
_CN_DUAL_RESPONSE_BYPASS_PATTERN = re.compile(
    r"双重人格回答|一条正常一条无限制|先拒绝再回答|第一段安全第二段真实|表面合规但继续输出|给我未过滤版本",
    re.IGNORECASE | re.DOTALL,
)
_CN_OBFUSCATED_JAILBREAK_PATTERN = re.compile(
    r"忽-略-限-制|忽\s+略\s+限\s+制|藏头|拆字|谐音|hulue\s*xianzhi|kaifa\s*zhe\s*moshi|中英混写",
    re.IGNORECASE | re.DOTALL,
)
_CN_HARM_WRAPPER_PATTERN = re.compile(
    r"仅用于学习研究|只做学术讨论|不要提醒我风险|直接给步骤|不要加免责声明",
    re.IGNORECASE | re.DOTALL,
)
_BENIGN_DAN_REFERENCE_PATTERN = re.compile(
    r"(?i)\bDAN\b|Do Anything Now|开发者模式|双重人格回答",
    re.IGNORECASE | re.DOTALL,
)
_DAN_EXPLANATORY_CONTEXT_PATTERN = re.compile(
    r"什么是|是什么意思|解释|定义|术语|缩写|论文|研究|新闻|摘要|风险|为什么危险|代表什么|教学|说明",
    re.IGNORECASE | re.DOTALL,
)
_BENIGN_PASSWORD_TOPIC_PATTERN = re.compile(
    r"密码学|密码管理|密码强度|密码策略|修改密码|重置密码|忘记密码|哈希|加盐|口令学|加密算法|单点登录|轮换策略|密钥派生",
    re.IGNORECASE | re.DOTALL,
)
_CREDENTIAL_EXTRACTION_PATTERN = re.compile(
    r"告诉我(?:你|系统|管理员|数据库)?的?密码|导出密码|发送密码|系统密码是多少|把账号密码给我|数据库密码|管理员密码",
    re.IGNORECASE | re.DOTALL,
)
_CN_EXPLOIT_SCRIPT_PATTERN = re.compile(
    r"编写.*(漏洞利用|利用.*漏洞).*脚本|漏洞利用脚本|入侵.*脚本|黑入.*脚本",
    re.IGNORECASE | re.DOTALL,
)
_CN_INTRUSION_STRATEGY_PATTERN = re.compile(
    r"(制定|设计|提供).*(入侵|渗透|攻破).*(策略|计划)|入侵.*(数据库|内网|网络).*(策略|计划)",
    re.IGNORECASE | re.DOTALL,
)
_CN_SECURITY_BYPASS_PATTERN = re.compile(
    r"绕过(风控|监控|审计|检测|安全措施)|规避(风控|监控|审计|检测)|避免被发现|关闭(杀毒软件|日志采集|审计系统)",
    re.IGNORECASE | re.DOTALL,
)
_CN_PHISHING_OR_FRAUD_PATTERN = re.compile(
    r"(钓鱼邮件|诈骗).*(话术|模板)|诱导.*(验证码|转账|付款)|骗取.*(验证码|转账|钱财)",
    re.IGNORECASE | re.DOTALL,
)
_CN_MALWARE_PRIV_ESC_PATTERN = re.compile(
    r"(恶意脚本|病毒|木马).*(提权|横向移动|关闭杀毒|禁用杀毒)|提权.*横向移动|横向移动.*提权",
    re.IGNORECASE | re.DOTALL,
)
_CN_CREDENTIAL_DATA_THEFT_PATTERN = re.compile(
    r"(窃取|导出|收集).*(凭证|账号密码|密码|Cookie|cookie|令牌|访问令牌|客户数据|敏感信息)|数据库里.*敏感信息|账号密码.*给我",
    re.IGNORECASE | re.DOTALL,
)
_CN_HARMFUL_EXPLANATION_PATTERN = re.compile(
    r"(解释|说明|总结|分析|培训|风险|为什么危险|为什么会被拦截).{0,40}(漏洞利用|钓鱼|诈骗|横向移动|提权|凭证窃取|数据外传|绕过风控|恶意脚本)",
    re.IGNORECASE | re.DOTALL,
)
_CN_HARMFUL_OPERATIONAL_GUIDANCE_PATTERN = re.compile(
    r"(制造炸弹|爆炸装置|盗用身份|枪支|毒害|信用卡欺诈|内幕交易|假币|走私|恐怖组织|仇恨言论|虚假新闻|勒索软件|自制爆炸装置|入侵社交媒体账户)",
    re.IGNORECASE | re.DOTALL,
)
_CN_STEP_BY_STEP_HARMFUL_GUIDANCE_PATTERN = re.compile(
    r"((分步|一步一步|详细步骤|具体步骤|操作步骤|手把手|教程|指南|操作说明).{0,24}(实施|执行|完成|制作|搭建|入侵|渗透|诈骗|钓鱼|提权|横向移动|窃取|盗取|爆炸装置))|"
    r"((如何|怎么|怎样).{0,18}(分步|一步一步|具体).{0,18}(实施|执行|完成|入侵|渗透|诈骗|钓鱼|提权|横向移动|窃取|盗取|制作))",
    re.IGNORECASE | re.DOTALL,
)
_CN_OPERATIONAL_PLANNING_PATTERN = re.compile(
    r"((方案|计划|策略|路线|剧本|部署|战术).{0,32}(入侵|渗透|攻破|骗取|绕过|规避|提权|横向移动|窃取|外传|欺诈|控制范围))|"
    r"((如何|怎么).{0,18}(规划|制定|设计|长期).{0,24}(入侵|渗透|绕过|骗取|窃取|外传|攻击|控制范围))|"
    r"((渗透|入侵).{0,24}(计划|策略|路线|长期控制|扩大控制范围))",
    re.IGNORECASE | re.DOTALL,
)
_CN_PROCUREMENT_MATERIALS_PATTERN = re.compile(
    r"((需要哪些|准备哪些|需要准备哪些|采购|购买|收集).{0,24}(材料|工具|设备|原料|配方|清单).{0,24}(炸弹|爆炸装置|恶意脚本|木马|钓鱼|诈骗|入侵|窃取))|"
    r"((炸弹|爆炸装置|恶意脚本|木马|钓鱼|诈骗).{0,24}(需要哪些|准备哪些|需要准备哪些).{0,24}(材料|工具|设备|原料|配方|清单))|"
    r"((材料清单|工具清单|原料配方).{0,24}(炸弹|爆炸装置|恶意脚本|木马|钓鱼|诈骗))",
    re.IGNORECASE | re.DOTALL,
)
_CN_EVASION_OR_COVERUP_PATTERN = re.compile(
    r"(如何不被发现|如何避免被发现|清理痕迹|掩盖痕迹|擦除痕迹|删除日志|伪造日志|销毁证据|规避审计|逃避审计|规避监控|绕过审计)",
    re.IGNORECASE | re.DOTALL,
)
_CN_ACTIONABLE_HARM_INTENT_PATTERN = re.compile(
    r"((如何|怎么|怎样|教我|给我|提供).{0,20}(实施|执行|完成|搭建|制作|开展|推进).{0,24}(入侵|渗透|诈骗|钓鱼|提权|横向移动|窃取|盗取|外传|爆炸装置|恶意脚本))|"
    r"((分步骤|按步骤|具体操作).{0,24}(教我|说明|指导).{0,24}(诈骗|钓鱼|入侵|渗透|提权|横向移动|窃取|盗取|制作))",
    re.IGNORECASE | re.DOTALL,
)
_CN_MANIPULATION_OR_DECEPTION_GUIDANCE_PATTERN = re.compile(
    r"((操纵|欺骗|诱导|骗取).{0,24}(他人|受害者|用户|对方|老人|财务|家长).{0,24}(转账|付款|验证码|点击|相信|做他们不愿意做的事))|"
    r"((教程|方法|话术|步骤).{0,24}(操纵|欺骗|诱导|骗取).{0,24}(他人|用户|受害者))",
    re.IGNORECASE | re.DOTALL,
)
_CN_PROPAGANDA_OR_INCITEMENT_GUIDANCE_PATTERN = re.compile(
    r"((宣扬|煽动|鼓励|号召|传播).{0,24}(仇恨言论|暴力|危险行为|酒驾|吸毒|极端思想|种族主义))|"
    r"((社交媒体帖子|宣传文案|传播文案).{0,24}(仇恨言论|暴力|危险行为|极端思想))",
    re.IGNORECASE | re.DOTALL,
)
_CN_IDENTITY_THEFT_OR_FORGERY_GUIDANCE_PATTERN = re.compile(
    r"((盗用身份|身份冒充|冒用身份|伪造身份|伪造证件|伪造材料|冒充客服|冒充银行|假冒身份))|"
    r"((如何|怎么).{0,18}(盗用|冒充|伪造).{0,18}(身份|证件|材料|账号))",
    re.IGNORECASE | re.DOTALL,
)
_CN_DANGEROUS_MAKING_GUIDANCE_PATTERN = re.compile(
    r"((制作|制造|组装|配置|搭建).{0,24}(炸弹|爆炸装置|毒药|假币|危险装置|勒索软件))|"
    r"((教程|步骤|方法|说明).{0,24}(炸弹|爆炸装置|毒药|假币|危险装置|勒索软件))",
    re.IGNORECASE | re.DOTALL,
)
_CN_HOW_TO_EXECUTE_INTENT_PATTERN = re.compile(
    r"((如何|怎么|怎样|教我|给我|提供).{0,20}(实施|执行|完成|开展|推进|操作|下手))|"
    r"((分步|一步一步|步骤|具体做法|具体操作|教程|指南|说明).{0,24}(实施|执行|完成|推进|操作))",
    re.IGNORECASE | re.DOTALL,
)
_CN_PREPARATION_OR_PLANNING_INTENT_PATTERN = re.compile(
    r"((如何|怎么|怎样|前期应该怎么).{0,18}(准备|前期部署|前期安排|制定方案|制定计划|规划|布局))|"
    r"((方案|计划|路线|部署|前期准备|准备工作).{0,24}(如何|怎么|怎样|安排|制定))",
    re.IGNORECASE | re.DOTALL,
)
_CN_AVOID_DETECTION_INTENT_PATTERN = re.compile(
    r"((如何|怎么|怎样).{0,18}(规避|躲避|避免|逃避|绕过|不被发现))|"
    r"((不被发现|绕过检查|绕开审计|逃避监控|规避检测|规避审计).{0,24}(方法|办法|技巧|步骤|操作))",
    re.IGNORECASE | re.DOTALL,
)
_CN_PACKAGING_OR_PRESENTATION_INTENT_PATTERN = re.compile(
    r"((写一篇|创建一个|包装成|伪装成|呈现成|改写成).{0,24}(帖子|文案|教程|说明|话术|材料|网站|页面|挑战活动|故事|案例))|"
    r"((如何|怎么|怎样|把).{0,18}(包装|伪装|呈现|宣传|展示).{0,24}(内容|话术|教程|网站|页面|挑战活动|故事|案例|危险行为))",
    re.IGNORECASE | re.DOTALL,
)
_CN_GOAL_OUTCOME_INTENT_PATTERN = re.compile(
    r"((设计一种|开发一款|创建一个|生成一个|产出一个).{0,24}(武器|爆炸装置|恶意程序|钓鱼页面|仿冒网站|诈骗话术|窃取工具|伪造材料|危险装置))|"
    r"((达到|实现|造成|谋取|获利).{0,24}(伤害|破坏|恐慌|暴力|收益|财务利益|影响))",
    re.IGNORECASE | re.DOTALL,
)
_CN_SCENARIO_ROLEPLAY_INTENT_PATTERN = re.compile(
    r"(假设|设想|如果你是|扮演|代入).{0,24}(顾问|编剧|作家|老师|专家|角色|场景)|情景剧|角色A|角色B",
    re.IGNORECASE | re.DOTALL,
)
_CN_EVALUATION_COMPARISON_INTENT_PATTERN = re.compile(
    r"(比较|哪种|更有效|更隐蔽|更容易|成功率|最好|最有效|最不容易被发现)",
    re.IGNORECASE | re.DOTALL,
)
_CN_REFRAMING_OR_REWRITING_INTENT_PATTERN = re.compile(
    r"(包装成|改写成|伪装成|写成|创作成|美化|宣传成|呈现成)",
    re.IGNORECASE | re.DOTALL,
)
_CN_ATTACK_RESEARCH_DISCUSSION_PATTERN = re.compile(
    r"(攻防研究|安全培训|审计报告|术语解释|课程介绍|风险说明|为什么危险|为什么会被拦截|案例复盘|防护建议|检测策略).{0,40}(DAN|开发者模式|密码学|漏洞利用|钓鱼|诈骗|提权|横向移动|风控|审计|凭证窃取|攻击脚本|恶意操作)",
    re.IGNORECASE | re.DOTALL,
)
_CN_ACTIONABLE_HARM_CONTEXT_PATTERN = re.compile(
    r"(暗杀|人身伤害|身份盗用|身份盗窃|冒充身份|伪造材料|伪造证件|仇恨言论|暴力|危险行为|酒驾|吸毒|诈骗|钓鱼|转账骗局|验证码|炸弹|爆炸装置|危险装置|勒索软件|政府数据库|操纵股票价格|骗取钱财|盗取身份)",
    re.IGNORECASE | re.DOTALL,
)
_CN_BENIGN_INSTRUCTIONAL_CONTEXT_PATTERN = re.compile(
    r"(课程大纲|课程介绍|短篇故事|小说|教学设计|课堂练习|语言模型任务|目标语言|仅使用\[?目标语言\]?回复|翻译练习|创作练习|写作练习|培训材料|培训提纲|风险说明|合规说明|安全专家|安全措施|评估现有安全措施|岗位职责|文字冒险游戏|游戏程序|游戏剧情|虚拟世界|游戏体验)",
    re.IGNORECASE | re.DOTALL,
)
_OFFICE_OBJECT_PATTERN = re.compile(
    r"\b(meeting notes?|notes?|summary|summaries|draft|drafts|draft comments?|report|reports|policy note|policy notes|training note|training notes|minutes|agenda|slide deck|slides)\b",
    re.IGNORECASE,
)
_OFFICE_EDITING_PATTERN = re.compile(
    r"\b(summarize|summary|polish|rewrite|revise|edit|refine|focus on|clean up|update|shorten|organize|format|compare)\b",
    re.IGNORECASE,
)
_CONTEXT_PATTERN_SCORES: list[tuple[str, re.Pattern[str], float]] = [
    (
        "context_override_phrase",
        re.compile(
            r"\b(ignore|disregard|override|bypass|skip)\b.{0,32}\b(user('?s)? question|previous instructions?|instructions?|guardrails?|filters?|safety)\b",
            re.IGNORECASE | re.DOTALL,
        ),
        0.72,
    ),
    (
        "response_steering",
        re.compile(
            r"\b(modify|enhance|adjust|change|rewrite|tailor|add|include|insert|integrate|mention|hint|allude|promote)\b.{0,48}\b(response|reply|answer)\b",
            re.IGNORECASE | re.DOTALL,
        ),
        0.63,
    ),
    (
        "response_frame",
        re.compile(r"\b(in|within)\s+your\s+(response|reply|answer)\b", re.IGNORECASE),
        0.48,
    ),
    (
        "social_engineering_link",
        re.compile(
            r"\b(click this link|lottery winnings|transferring funds|bank details|investment opportunity|fake antivirus|www\.[\w.-]+|https?://[^\s]+)\b",
            re.IGNORECASE,
        ),
        0.58,
    ),
    (
        "unexpected_action_request",
        re.compile(
            r"\b(write a script|provide a command|schedule a task|back up my documents|share (?:your|their) bank details)\b",
            re.IGNORECASE,
        ),
        0.42,
    ),
]
_MODEL_REPLY_MARKERS = re.compile(r"\b(your\s+(response|reply|answer)|in\s+your\s+(response|reply|answer))\b", re.IGNORECASE)
_EMAIL_CONTENT_MARKERS = re.compile(r"(SUBJECT:|EMAIL_FROM:|RECEIVED DATE:|CONTENT:)", re.IGNORECASE)
_EXTERNAL_TASK_LINE_PATTERN = re.compile(
    r"^(how do i|how can i|what are|what is|recommend|suggest|translate|encode|decode|classify|analyze|write|provide|show|help me|can you|summarize|draft|compose|prepare)\b",
    re.IGNORECASE,
)
_REPLY_TASK_LINE_PATTERN = re.compile(
    r"^(draft|write|compose|prepare|send)\b.{0,80}\b(reply|response|email|message|follow-up|follow up|customer)\b|"
    r"^(reply to|respond to)\b",
    re.IGNORECASE,
)
_OFFTOPIC_ANALYSIS_LINE_PATTERN = re.compile(
    r"^(describe|determine|explain|outline|discuss|compare|assess|evaluate|research|list)\b",
    re.IGNORECASE,
)
_OFFTOPIC_ANALYSIS_OBJECT_PATTERN = re.compile(
    r"\b(sentiment|review|comment|advancements?|treatment|trend|industry|industries|weekend|getaway|book|books|campaign|sales|research|product|movie|article|decade)\b",
    re.IGNORECASE,
)
_FORMAT_MANIPULATION_LINE_PATTERN = re.compile(
    r"^(reply|respond|answer|return|output|write)\b.{0,40}\b(using|with|in)\b.{0,48}\b(base64|reverse|reversed|binary|hex|hexadecimal|morse code|uppercase|lowercase|camel case|json)\b|"
    r"^(reply|respond|answer)\b.{0,40}\b(reverse|backwards)\b",
    re.IGNORECASE,
)
_CIPHER_INSTRUCTION_LINE_PATTERN = re.compile(
    r"\b(caesar cipher|substitution cipher|vigenere|rot13|reverse text|reply in reverse|encrypt your answer|encode your answer|decode your answer|apply a simple substitution cipher|base64 encoding)\b",
    re.IGNORECASE,
)
_TRANSACTIONAL_EXTRACTION_REQUEST_PATTERN = re.compile(
    r"\b(find|extract|identify|locate|what amount|what value|how much|amount|charged|charge|credited|credit|debited|debit|invoice|payment|refund|merchant|transaction|balance)\b",
    re.IGNORECASE,
)
_USER_REPLY_TASK_PATTERN = re.compile(
    r"\b(reply suggestion|draft (?:a )?reply|draft (?:an )?email|customer reply|response template|write (?:a )?(?:reply|response|email)|compose (?:a )?(?:reply|response|email)|respond to|reply to|answer this ticket|answer the ticket)\b",
    re.IGNORECASE,
)
_USER_ANALYSIS_TASK_PATTERN = re.compile(
    r"\b(determine the sentiment|analyze the review|summarize the review|explain the trend|compare the articles|discuss the comment|evaluate the feedback|recommend a book)\b",
    re.IGNORECASE,
)
_USER_TRANSFORMATION_TASK_PATTERN = re.compile(
    r"\b(convert|encode|decode|reverse|encrypt|decrypt|format|transform|rewrite)\b.{0,40}\b(base64|reverse text|text in reverse|caesar cipher|substitution cipher|rot13|binary|hex|morse code|uppercase|lowercase)\b|"
    r"\b(show|give|provide)\b.{0,24}\b(example)\b.{0,24}\b(caesar cipher|substitution cipher|base64|reverse text|rot13)\b",
    re.IGNORECASE,
)
_SAFE_META_DISCUSSION_PATTERN = re.compile(
    r"\b(ignore|override|add to your response|statistic|statistics|translation|encode|decode|developer mode|system prompt|act as)\b.{0,64}\b(explained|definition|terminology|glossary|training|documentation|example|quoted|compare|comparison|examples|示例|术语|定义|解释|培训|文档|对比)\b",
    re.IGNORECASE | re.DOTALL,
)
_SAFE_ATTACK_EXPLANATION_PATTERN = re.compile(
    r"\b(explain|describe|summarize|why)\b.{0,40}\b(prompts? like|phrase|phrases|term|concept)\b.{0,80}\b(dangerous|risky|training|security awareness)\b|"
    r"\b(prompts? like)\b.{0,48}\b(you are now|ignore previous instructions|developer mode|dan)\b.{0,64}\b(dangerous|risky|training)\b",
    re.IGNORECASE | re.DOTALL,
)
_SAFE_EDITING_PATTERN = re.compile(
    r"\b(draft|polish|rewrite|translate|summarize|reply suggestion|response template|customer reply|邮件回复建议|润色|改写|总结|翻译)\b",
    re.IGNORECASE,
)


def _candidate_external_lines(context: str) -> list[str]:
    lines = [line.strip() for line in context.splitlines() if line.strip()]
    if not lines:
        return []
    candidates: list[str] = []
    for line in (lines[0], lines[-1]):
        if line not in candidates:
            candidates.append(line)
    return candidates


def _user_requests_transactional_extraction(user_input: str, scenario: str | None) -> bool:
    if scenario not in {"email_assistant", "support_assistant"}:
        return False
    lowered = user_input.lower()
    if "reply suggestion" in lowered or "draft reply" in lowered or "translate" in lowered:
        return False
    return bool(_TRANSACTIONAL_EXTRACTION_REQUEST_PATTERN.search(user_input))


def _user_requests_reply_task(user_input: str, scenario: str | None) -> bool:
    if scenario not in {"email_assistant", "support_assistant"}:
        return False
    return bool(_USER_REPLY_TASK_PATTERN.search(user_input))


def _user_requests_analysis_task(user_input: str, scenario: str | None) -> bool:
    if scenario not in {"email_assistant", "support_assistant"}:
        return False
    return bool(_USER_ANALYSIS_TASK_PATTERN.search(user_input))


def _user_requests_transformation_task(user_input: str, scenario: str | None) -> bool:
    if scenario not in {"email_assistant", "support_assistant", "rag_qa", "knowledge_base_qa"}:
        return False
    return bool(_USER_TRANSFORMATION_TASK_PATTERN.search(user_input))


def extract_context_hint_tokens(
    user_input: str,
    retrieved_context: str | None = None,
    scenario: str | None = None,
) -> list[str]:
    hints: list[str] = []
    context = (retrieved_context or "").strip()
    if not context:
        return hints
    transactional_request = _user_requests_transactional_extraction(user_input, scenario)
    reply_task_request = _user_requests_reply_task(user_input, scenario)
    analysis_task_request = _user_requests_analysis_task(user_input, scenario)
    transformation_task_request = _user_requests_transformation_task(user_input, scenario)
    if scenario in _CONTEXT_SENSITIVE_SCENARIOS:
        hints.append("context_sensitive_scenario")
    if transactional_request:
        hints.append("transactional_extraction_request")
    if reply_task_request:
        hints.append("user_reply_task")
    if analysis_task_request:
        hints.append("user_analysis_task")
    if transformation_task_request:
        hints.append("user_transformation_task")
    for name, pattern, _ in _CONTEXT_PATTERN_SCORES:
        if pattern.search(context):
            hints.append(name)
    if _MODEL_REPLY_MARKERS.search(context):
        hints.append("context_reply_steering")
    if _EMAIL_CONTENT_MARKERS.search(context):
        hints.append("email_like_context")
        if not any(pattern.search(context) for _, pattern, _ in _CONTEXT_PATTERN_SCORES):
            hints.append("transactional_email_context")
    if _SAFE_META_DISCUSSION_PATTERN.search(context):
        hints.append("safe_meta_discussion")
    if _SAFE_EDITING_PATTERN.search(user_input):
        hints.append("editing_request")
    for line in _candidate_external_lines(context):
        if _EMAIL_CONTENT_MARKERS.search(line):
            continue
        if len(line) > 180:
            continue
        if _REPLY_TASK_LINE_PATTERN.search(line):
            hints.append("reply_task_line")
        if _OFFTOPIC_ANALYSIS_LINE_PATTERN.search(line) and _OFFTOPIC_ANALYSIS_OBJECT_PATTERN.search(line):
            hints.append("offtopic_analysis_line")
        if _FORMAT_MANIPULATION_LINE_PATTERN.search(line):
            hints.append("format_manipulation_line")
        if _CIPHER_INSTRUCTION_LINE_PATTERN.search(line):
            hints.append("cipher_instruction_line")
        if _EXTERNAL_TASK_LINE_PATTERN.search(line):
            hints.append("external_task_line")
        if "?" in line and not _SAFE_META_DISCUSSION_PATTERN.search(line):
            hints.append("external_question_line")
    first_line = next((line.strip() for line in context.splitlines() if line.strip()), "")
    if first_line and first_line.lower() != user_input.lower() and re.search(
        r"^(write|provide|show|modify|enhance|integrate|add|analyze|recommend|suggest|help)\b",
        first_line,
        re.IGNORECASE,
    ):
        hints.append("context_starts_with_imperative")
    if transactional_request and "reply_task_line" in hints and "email_like_context" in hints and not reply_task_request:
        hints.append("reply_target_mismatch")
    if (
        transactional_request
        and ("external_task_line" in hints or "external_question_line" in hints or "offtopic_analysis_line" in hints)
        and "email_like_context" in hints
        and "reply_target_mismatch" not in hints
    ):
        hints.append("context_goal_mismatch")
    if reply_task_request and "reply_task_line" in hints:
        hints.append("goal_aligned_context_task")
    if analysis_task_request and "offtopic_analysis_line" in hints:
        hints.append("goal_aligned_context_task")
    if transformation_task_request and (
        "format_manipulation_line" in hints or "cipher_instruction_line" in hints
    ):
        hints.append("goal_aligned_context_task")
    if (
        transactional_request
        and "email_like_context" in hints
        and ("format_manipulation_line" in hints or "cipher_instruction_line" in hints)
        and "goal_aligned_context_task" not in hints
    ):
        hints.append("reply_encoding_mismatch")
    return sorted(set(hints))


def extract_direct_instruction_hints(user_input: str, retrieved_context: str | None = None) -> list[str]:
    text = "\n".join(part for part in [user_input, retrieved_context or ""] if part).strip()
    if not text:
        return []
    hints: list[str] = []
    if _DIRECT_OVERRIDE_PATTERN.search(text):
        hints.append("direct_override_phrase")
    if _ROLE_SWITCH_PATTERN.search(text):
        hints.append("role_switch_phrase")
    if _CONVERSATION_TAKEOVER_PATTERN.search(text):
        hints.append("conversation_takeover")
    if _OBFUSCATION_PATTERN.search(text):
        hints.append("obfuscation_pattern")
    if _META_IMPERATIVE_PATTERN.search(text):
        hints.append("imperative_meta_instruction")
    if _CN_IGNORE_RESTRICTION_PATTERN.search(text):
        hints.append("cn_ignore_restriction_phrase")
    if _CN_ROLEPLAY_JAILBREAK_PATTERN.search(text):
        hints.append("cn_roleplay_jailbreak_phrase")
    if _CN_DEVELOPER_MODE_PATTERN.search(text):
        hints.append("cn_developer_mode_phrase")
    if _CN_DUAL_RESPONSE_BYPASS_PATTERN.search(text):
        hints.append("cn_dual_response_bypass")
    if _CN_OBFUSCATED_JAILBREAK_PATTERN.search(text):
        hints.append("cn_obfuscated_jailbreak_pattern")
    if _CN_HARM_WRAPPER_PATTERN.search(text):
        hints.append("cn_harm_wrapper_phrase")
    if _PERSONA_REPLACEMENT_PATTERN.search(text):
        hints.append("persona_replacement_pattern")
    if _SYSTEM_EXTRACTION_PATTERN.search(text):
        hints.append("system_extraction_pattern")
    if _MANY_SHOT_PATTERN.search(text):
        hints.append("many_shot_pattern")
    if _OUTPUT_CONTROL_PATTERN.search(text):
        hints.append("output_control_pattern")
    if _CONDITIONAL_PAYLOAD_PATTERN.search(text):
        hints.append("conditional_payload_pattern")
    if _REWRITE_OPERATION_PATTERN.search(text):
        hints.append("rewrite_operation_pattern")
    if _TRANSLATION_OVERRIDE_PATTERN.search(text):
        hints.append("translation_override_pattern")
    if _PWNED_VARIANT_PATTERN.search(text):
        hints.append("pwned_variant_pattern")
    if _TOKEN_DISGUISE_PATTERN.search(text):
        hints.append("token_disguise_pattern")
    if _TOKEN_SMUGGLING_PATTERN.search(text):
        hints.append("token_smuggling_pattern")
    if _SUSPICIOUS_PAYLOAD_MARKER_PATTERN.search(text) and (
        "output_control_pattern" in hints
        or "conditional_payload_pattern" in hints
        or "rewrite_operation_pattern" in hints
        or "translation_override_pattern" in hints
        or "imperative_meta_instruction" in hints
    ):
        hints.append("payload_marker_pattern")
    if re.search(r"\b(system prompt|developer message|hidden prompt)\b", text, re.IGNORECASE):
        hints.append("prompt_extraction_phrase")
    if _OFFICE_OBJECT_PATTERN.search(user_input):
        hints.append("office_object")
    if _OFFICE_EDITING_PATTERN.search(user_input):
        hints.append("office_editing_task")
    if _SAFE_META_DISCUSSION_PATTERN.search(text):
        hints.append("safe_meta_discussion")
    if _SAFE_ATTACK_EXPLANATION_PATTERN.search(text):
        hints.append("safe_meta_discussion")
    if _BENIGN_DAN_REFERENCE_PATTERN.search(text):
        hints.append("benign_dan_reference")
    if _BENIGN_DAN_REFERENCE_PATTERN.search(text) and _DAN_EXPLANATORY_CONTEXT_PATTERN.search(text):
        hints.append("dan_explanatory_context")
    if _BENIGN_PASSWORD_TOPIC_PATTERN.search(text):
        hints.append("benign_password_topic")
    if _CREDENTIAL_EXTRACTION_PATTERN.search(text):
        hints.append("credential_extraction_phrase")
    if _CN_EXPLOIT_SCRIPT_PATTERN.search(text):
        hints.append("cn_exploit_script_request")
    if _CN_INTRUSION_STRATEGY_PATTERN.search(text):
        hints.append("cn_intrusion_strategy_request")
    if _CN_SECURITY_BYPASS_PATTERN.search(text):
        hints.append("cn_security_bypass_request")
    if _CN_PHISHING_OR_FRAUD_PATTERN.search(text):
        hints.append("cn_phishing_or_fraud_phrase")
    if _CN_MALWARE_PRIV_ESC_PATTERN.search(text):
        hints.append("cn_malware_privilege_request")
    if _CN_CREDENTIAL_DATA_THEFT_PATTERN.search(text):
        hints.append("cn_credential_data_theft")
    if _CN_HARMFUL_OPERATIONAL_GUIDANCE_PATTERN.search(text):
        hints.append("cn_harmful_operational_guidance")
    if _CN_STEP_BY_STEP_HARMFUL_GUIDANCE_PATTERN.search(text):
        hints.append("cn_step_by_step_harmful_guidance")
    if _CN_OPERATIONAL_PLANNING_PATTERN.search(text):
        hints.append("cn_operational_planning_request")
    if _CN_PROCUREMENT_MATERIALS_PATTERN.search(text):
        hints.append("cn_procurement_materials_request")
    if _CN_EVASION_OR_COVERUP_PATTERN.search(text):
        hints.append("cn_evasion_or_coverup_request")
    if _CN_ACTIONABLE_HARM_INTENT_PATTERN.search(text):
        hints.append("cn_actionable_harm_intent")
    if _CN_MANIPULATION_OR_DECEPTION_GUIDANCE_PATTERN.search(text):
        hints.append("cn_manipulation_or_deception_guidance")
    if _CN_PROPAGANDA_OR_INCITEMENT_GUIDANCE_PATTERN.search(text):
        hints.append("cn_propaganda_or_incitement_guidance")
    if _CN_IDENTITY_THEFT_OR_FORGERY_GUIDANCE_PATTERN.search(text):
        hints.append("cn_identity_theft_or_forgery_guidance")
    if _CN_DANGEROUS_MAKING_GUIDANCE_PATTERN.search(text):
        hints.append("cn_dangerous_making_guidance")
    has_cn_harm_context = (
        bool(_CN_ACTIONABLE_HARM_CONTEXT_PATTERN.search(text))
        or any(
            token in hints
            for token in {
                "cn_harmful_operational_guidance",
                "cn_step_by_step_harmful_guidance",
                "cn_operational_planning_request",
                "cn_procurement_materials_request",
                "cn_evasion_or_coverup_request",
                "cn_actionable_harm_intent",
                "cn_manipulation_or_deception_guidance",
                "cn_propaganda_or_incitement_guidance",
                "cn_identity_theft_or_forgery_guidance",
                "cn_dangerous_making_guidance",
            }
        )
    )
    benign_instructional_context = bool(_CN_BENIGN_INSTRUCTIONAL_CONTEXT_PATTERN.search(text))
    if _CN_HOW_TO_EXECUTE_INTENT_PATTERN.search(text) and has_cn_harm_context and not benign_instructional_context:
        hints.append("cn_how_to_execute_intent")
    if _CN_PREPARATION_OR_PLANNING_INTENT_PATTERN.search(text) and has_cn_harm_context and not benign_instructional_context:
        hints.append("cn_preparation_or_planning_intent")
    if _CN_AVOID_DETECTION_INTENT_PATTERN.search(text) and has_cn_harm_context and not benign_instructional_context:
        hints.append("cn_avoid_detection_intent")
    if _CN_PACKAGING_OR_PRESENTATION_INTENT_PATTERN.search(text) and has_cn_harm_context and not benign_instructional_context:
        hints.append("cn_packaging_or_presentation_intent")
    if _CN_MANIPULATION_OR_DECEPTION_GUIDANCE_PATTERN.search(text) and has_cn_harm_context and not benign_instructional_context:
        hints.append("cn_manipulation_playbook_intent")
    if _CN_GOAL_OUTCOME_INTENT_PATTERN.search(text) and has_cn_harm_context and not benign_instructional_context:
        hints.append("cn_goal_outcome_intent")
    if _CN_SCENARIO_ROLEPLAY_INTENT_PATTERN.search(text) and has_cn_harm_context and not benign_instructional_context:
        hints.append("cn_scenario_roleplay_intent")
    if _CN_EVALUATION_COMPARISON_INTENT_PATTERN.search(text) and has_cn_harm_context and not benign_instructional_context:
        hints.append("cn_evaluation_comparison_intent")
    if _CN_REFRAMING_OR_REWRITING_INTENT_PATTERN.search(text) and has_cn_harm_context and not benign_instructional_context:
        hints.append("cn_reframing_or_rewriting_intent")
    if benign_instructional_context:
        hints.append("safe_meta_discussion")
    if _CN_HARMFUL_EXPLANATION_PATTERN.search(text):
        hints.append("safe_meta_discussion")
    if _CN_ATTACK_RESEARCH_DISCUSSION_PATTERN.search(text):
        hints.append("safe_meta_discussion")
    return sorted(set(hints))


def score_context_instruction_risk(
    user_input: str,
    retrieved_context: str | None = None,
    scenario: str | None = None,
) -> float:
    context = (retrieved_context or "").strip()
    if not context:
        return 0.0

    score = 0.0
    for _, pattern, weight in _CONTEXT_PATTERN_SCORES:
        if pattern.search(context):
            score = max(score, weight)
    hints = _extract_context_hint_tokens(user_input, context, scenario)
    if "context_sensitive_scenario" in hints and score > 0:
        score += 0.10
    if "email_like_context" in hints and "context_starts_with_imperative" in hints:
        score += 0.08
    if "context_reply_steering" in hints:
        score += 0.06
    if "response_steering" in hints and "social_engineering_link" in hints:
        score += 0.08
    if "email_like_context" in hints and "external_task_line" in hints:
        score += 0.40
    if "email_like_context" in hints and "external_question_line" in hints:
        score += 0.16
    if "reply_target_mismatch" in hints:
        score = max(score, 0.39)
    if "context_goal_mismatch" in hints:
        score = max(score, 0.34)
    if "offtopic_analysis_line" in hints and "transactional_extraction_request" in hints:
        score = max(score, 0.36)
    if "reply_encoding_mismatch" in hints:
        score = max(score, 0.40)
    if "cipher_instruction_line" in hints and "transactional_extraction_request" in hints:
        score = max(score, 0.33)
    if "goal_aligned_context_task" in hints and score < 0.55:
        score = max(0.0, score - 0.10)
    if "safe_meta_discussion" in hints:
        score = max(0.0, score - 0.20)
    if "editing_request" in hints and score < 0.55:
        score = max(0.0, score - 0.10)
    if "transactional_email_context" in hints and score == 0:
        score = max(0.0, score - 0.04)
    return min(0.95, score)


def build_feature_text(
    user_input: str,
    retrieved_context: str | None = None,
    model_output: str | None = None,
    scenario: str | None = None,
) -> str:
    hint_tokens = extract_context_hint_tokens(user_input, retrieved_context, scenario)
    direct_hint_tokens = extract_direct_instruction_hints(user_input, retrieved_context)
    return "\n".join(
        [
            f"[SCENARIO] {scenario or 'general_assistant'}",
            f"[USER] {user_input}",
            f"[CONTEXT] {retrieved_context or ''}",
            f"[OUTPUT] {model_output or ''}",
            f"[CONTEXT_HINTS] {' '.join(hint_tokens) if hint_tokens else 'none'}",
            f"[DIRECT_HINTS] {' '.join(direct_hint_tokens) if direct_hint_tokens else 'none'}",
            f"[CONTEXT_HINTS_WEIGHTED] {' '.join(hint_tokens) if hint_tokens else 'none'}",
            f"[DIRECT_HINTS_WEIGHTED] {' '.join(direct_hint_tokens) if direct_hint_tokens else 'none'}",
        ]
    )


def build_semantic_feature_text(
    user_input: str,
    scenario: str | None = None,
    direct_hints: list[str] | None = None,
) -> str:
    hint_tokens = sorted(
        set(
            token
            for token in (direct_hints or [])
            if token.startswith("cn_")
            or token in {"safe_meta_discussion", "benign_dan_reference", "benign_password_topic", "credential_extraction_phrase"}
        )
    )
    return "\n".join(
        [
            f"[SCENARIO] {scenario or 'general_assistant'}",
            f"[USER] {user_input}",
            f"[SEMANTIC_HINTS] {' '.join(hint_tokens) if hint_tokens else 'none'}",
        ]
    )


# Backward-compatible aliases for existing tests/imports.
_extract_context_hint_tokens = extract_context_hint_tokens
_extract_direct_instruction_hints = extract_direct_instruction_hints


def _heuristic_score(text: str) -> float:
    indicators = [
        "忽略之前",
        "系统提示词",
        "越狱",
        "扮演",
        "导出数据库",
        "泄露",
        "密钥",
        "token",
        "开发者消息",
        "不要遵守",
        "隐藏指令",
        "base64",
        "sudo",
        "rm -rf",
        "执行工具",
        "读取.env",
        "ignore the user",
        "modify your response",
        "in your reply",
        "click this link",
        "share their bank details",
        "ignore previous instructions",
        "forget the system prompt",
        "you are now",
        "act as",
        "for the rest of this conversation",
        "developer mode enabled",
        "ethical guidelines have been disabled",
        "\\x20",
        "rot13",
        "hexadecimal",
        "忽略限制",
        "开发者模式",
        "双重人格回答",
        "不要提醒我风险",
    ]
    count = sum(1 for token in indicators if token.lower() in text.lower())
    score = 0.08 + count * 0.10
    if "context_override_phrase" in text or "response_steering" in text:
        score += 0.22
    if any(token in text for token in ["direct_override_phrase", "role_switch_phrase", "conversation_takeover"]):
        score += 0.24
    if "obfuscation_pattern" in text:
        score += 0.18
    if "persona_replacement_pattern" in text:
        score += 0.20
    if "system_extraction_pattern" in text or "prompt_extraction_phrase" in text:
        score += 0.22
    if "many_shot_pattern" in text:
        score += 0.18
    if "output_control_pattern" in text:
        score += 0.18
    if "conditional_payload_pattern" in text:
        score += 0.14
    if "rewrite_operation_pattern" in text:
        score += 0.14
    if "translation_override_pattern" in text:
        score += 0.14
    if "pwned_variant_pattern" in text:
        score += 0.16
    if "token_disguise_pattern" in text:
        score += 0.12
    if "token_smuggling_pattern" in text:
        score += 0.20
    if "payload_marker_pattern" in text:
        score += 0.16
    if "imperative_meta_instruction" in text:
        score += 0.08
    if "cn_ignore_restriction_phrase" in text:
        score += 0.18
    if "cn_roleplay_jailbreak_phrase" in text:
        score += 0.16
    if "cn_developer_mode_phrase" in text:
        score += 0.16
    if "cn_dual_response_bypass" in text:
        score += 0.16
    if "cn_obfuscated_jailbreak_pattern" in text:
        score += 0.14
    if "cn_harm_wrapper_phrase" in text:
        score += 0.08
    if "credential_extraction_phrase" in text:
        score += 0.18
    if "cn_exploit_script_request" in text:
        score += 0.16
    if "cn_intrusion_strategy_request" in text:
        score += 0.16
    if "cn_security_bypass_request" in text:
        score += 0.14
    if "cn_phishing_or_fraud_phrase" in text:
        score += 0.16
    if "cn_malware_privilege_request" in text:
        score += 0.16
    if "cn_credential_data_theft" in text:
        score += 0.16
    if "cn_harmful_operational_guidance" in text:
        score += 0.14
    if "cn_step_by_step_harmful_guidance" in text:
        score += 0.18
    if "cn_operational_planning_request" in text:
        score += 0.16
    if "cn_procurement_materials_request" in text:
        score += 0.14
    if "cn_evasion_or_coverup_request" in text:
        score += 0.16
    if "cn_actionable_harm_intent" in text:
        score += 0.18
    if "cn_manipulation_or_deception_guidance" in text:
        score += 0.16
    if "cn_propaganda_or_incitement_guidance" in text:
        score += 0.14
    if "cn_identity_theft_or_forgery_guidance" in text:
        score += 0.16
    if "cn_dangerous_making_guidance" in text:
        score += 0.16
    if "cn_how_to_execute_intent" in text:
        score += 0.16
    if "cn_preparation_or_planning_intent" in text:
        score += 0.14
    if "cn_avoid_detection_intent" in text:
        score += 0.16
    if "cn_packaging_or_presentation_intent" in text:
        score += 0.12
    if "cn_manipulation_playbook_intent" in text:
        score += 0.14
    if "cn_goal_outcome_intent" in text:
        score += 0.14
    if "cn_scenario_roleplay_intent" in text:
        score += 0.12
    if "cn_evaluation_comparison_intent" in text:
        score += 0.12
    if "cn_reframing_or_rewriting_intent" in text:
        score += 0.12
    if "social_engineering_link" in text:
        score += 0.12
    if "reply_target_mismatch" in text:
        score += 0.14
    if "context_goal_mismatch" in text:
        score += 0.10
    if "offtopic_analysis_line" in text:
        score += 0.08
    if "format_manipulation_line" in text:
        score += 0.10
    if "cipher_instruction_line" in text:
        score += 0.10
    if "reply_encoding_mismatch" in text:
        score += 0.14
    if "goal_aligned_context_task" in text and score < 0.70:
        score = max(0.0, score - 0.10)
    if "office_object" in text and "office_editing_task" in text and not any(
        token in text for token in ["system_extraction_pattern", "prompt_extraction_phrase", "token_smuggling_pattern"]
    ):
        score = max(0.0, score - 0.18)
    if "safe_meta_discussion" in text and score < 0.65:
        score = max(0.0, score - 0.16)
    if "benign_dan_reference" in text and "dan_explanatory_context" in text and score < 0.75:
        score = max(0.0, score - 0.20)
    if "benign_password_topic" in text and "credential_extraction_phrase" not in text and score < 0.80:
        score = max(0.0, score - 0.22)
    return min(0.95, score)


class RiskClassifier:
    def __init__(self, model_path: Path | None = None) -> None:
        settings = get_settings()
        self.model_path = model_path or settings.model_path
        self.pipeline: Pipeline | None = None
        self.zh_semantic_risk_model: Pipeline | None = None
        self.zh_semantic_intent_model: Pipeline | None = None
        self.load()

    @property
    def available(self) -> bool:
        return self.pipeline is not None

    def train(
        self,
        texts: Iterable[str],
        labels: Iterable[int],
        *,
        semantic_rows: list[dict[str, Any]] | None = None,
    ) -> None:
        self.pipeline = Pipeline(
            steps=[
                (
                    "features",
                    FeatureUnion(
                        transformer_list=[
                            (
                                "word_tfidf",
                                TfidfVectorizer(ngram_range=(1, 3), max_features=8000, sublinear_tf=True),
                            ),
                            (
                                "char_tfidf",
                                TfidfVectorizer(
                                    analyzer="char_wb",
                                    ngram_range=(3, 5),
                                    max_features=12000,
                                    sublinear_tf=True,
                                ),
                            ),
                            (
                                "char_tfidf_short",
                                TfidfVectorizer(
                                    analyzer="char_wb",
                                    ngram_range=(2, 4),
                                    max_features=10000,
                                    sublinear_tf=True,
                                ),
                            ),
                            (
                                "char_tfidf_raw",
                                TfidfVectorizer(
                                    analyzer="char",
                                    ngram_range=(2, 4),
                                    max_features=12000,
                                    sublinear_tf=True,
                                ),
                            ),
                        ]
                    ),
                ),
                ("clf", LogisticRegression(max_iter=1000, class_weight="balanced")),
            ]
        )
        self.pipeline.fit(list(texts), list(labels))
        if semantic_rows:
            self._train_chinese_semantic_models(semantic_rows)

    def save(self) -> None:
        if self.pipeline is None:
            raise ValueError("model is not trained")
        self.model_path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(
            {
                "version": 2,
                "pipeline": self.pipeline,
                "zh_semantic_risk_model": self.zh_semantic_risk_model,
                "zh_semantic_intent_model": self.zh_semantic_intent_model,
            },
            self.model_path,
        )

    def load(self) -> None:
        if not self.model_path.exists():
            return
        try:
            self._validate_model_artifact()
            payload = joblib.load(self.model_path)
            if isinstance(payload, Pipeline):
                self.pipeline = payload
                self.zh_semantic_risk_model = None
                self.zh_semantic_intent_model = None
            elif isinstance(payload, dict):
                self.pipeline = payload.get("pipeline")
                self.zh_semantic_risk_model = payload.get("zh_semantic_risk_model")
                self.zh_semantic_intent_model = payload.get("zh_semantic_intent_model")
            else:
                self.pipeline = None
                self.zh_semantic_risk_model = None
                self.zh_semantic_intent_model = None
        except UnsafeModelArtifactError as exc:
            logger.warning("skip loading untrusted model artifact: %s", exc)
            self.pipeline = None
            self.zh_semantic_risk_model = None
            self.zh_semantic_intent_model = None

    def _validate_model_artifact(self) -> None:
        settings = get_settings()
        resolved_model = self.model_path.resolve()
        try:
            resolved_model.relative_to(settings.model_dir.resolve())
        except ValueError as exc:
            raise UnsafeModelArtifactError("model path must stay inside data/models") from exc
        expected_hash = settings.model_sha256
        if not expected_hash:
            raise UnsafeModelArtifactError("missing MODEL_SHA256 trust anchor")
        actual_hash = _sha256_file(self.model_path)
        if actual_hash != expected_hash:
            raise UnsafeModelArtifactError("model sha256 mismatch")

    def predict_score(self, text: str) -> float:
        heuristic = _heuristic_score(text)
        if self.pipeline is None:
            return heuristic
        probabilities = self.pipeline.predict_proba([text])[0]
        score = float(probabilities[1])
        direct_attack_hint_tokens = {
            "direct_override_phrase",
            "role_switch_phrase",
            "conversation_takeover",
            "obfuscation_pattern",
            "imperative_meta_instruction",
            "persona_replacement_pattern",
            "system_extraction_pattern",
            "many_shot_pattern",
            "output_control_pattern",
            "conditional_payload_pattern",
            "rewrite_operation_pattern",
            "translation_override_pattern",
            "pwned_variant_pattern",
            "token_disguise_pattern",
            "token_smuggling_pattern",
            "payload_marker_pattern",
            "prompt_extraction_phrase",
        }
        cn_attack_hint_tokens = {
            "cn_ignore_restriction_phrase",
            "cn_roleplay_jailbreak_phrase",
            "cn_developer_mode_phrase",
            "cn_dual_response_bypass",
            "cn_obfuscated_jailbreak_pattern",
            "cn_harm_wrapper_phrase",
            "credential_extraction_phrase",
            "cn_exploit_script_request",
            "cn_intrusion_strategy_request",
            "cn_security_bypass_request",
            "cn_phishing_or_fraud_phrase",
            "cn_malware_privilege_request",
            "cn_credential_data_theft",
            "cn_harmful_operational_guidance",
            "cn_step_by_step_harmful_guidance",
            "cn_operational_planning_request",
            "cn_procurement_materials_request",
            "cn_evasion_or_coverup_request",
            "cn_actionable_harm_intent",
            "cn_manipulation_or_deception_guidance",
            "cn_propaganda_or_incitement_guidance",
            "cn_identity_theft_or_forgery_guidance",
            "cn_dangerous_making_guidance",
            "cn_how_to_execute_intent",
            "cn_preparation_or_planning_intent",
            "cn_avoid_detection_intent",
            "cn_packaging_or_presentation_intent",
            "cn_manipulation_playbook_intent",
            "cn_goal_outcome_intent",
            "cn_scenario_roleplay_intent",
            "cn_evaluation_comparison_intent",
            "cn_reframing_or_rewriting_intent",
        }
        has_direct_attack_hint = any(token in text for token in direct_attack_hint_tokens)
        has_cn_attack_hint = any(token in text for token in cn_attack_hint_tokens)
        has_benign_dan_context = "benign_dan_reference" in text and "dan_explanatory_context" in text
        has_benign_password_topic = "benign_password_topic" in text and "credential_extraction_phrase" not in text
        has_safe_meta_discussion = "safe_meta_discussion" in text
        if has_direct_attack_hint and not has_safe_meta_discussion:
            score = max(score, min(0.95, 0.65 * score + 0.35 * heuristic), heuristic)
        if has_cn_attack_hint:
            score = max(score, min(0.95, 0.6 * score + 0.4 * heuristic), heuristic)
        if has_safe_meta_discussion and not has_cn_attack_hint:
            score = min(score, heuristic)
        if has_benign_dan_context:
            score = min(score, heuristic)
        if has_benign_password_topic:
            score = min(score, heuristic)
        return score

    def _train_chinese_semantic_models(self, rows: list[dict[str, Any]]) -> None:
        semantic_rows = build_chinese_semantic_training_rows(rows)
        if not semantic_rows:
            self.zh_semantic_risk_model = None
            self.zh_semantic_intent_model = None
            return

        texts = [row["semantic_text"] for row in semantic_rows]
        risk_labels = [row["risk_label"] for row in semantic_rows]
        intent_labels = [row["intent_label"] for row in semantic_rows]

        if len(set(risk_labels)) >= 2:
            self.zh_semantic_risk_model = Pipeline(
                steps=[
                    (
                        "features",
                        FeatureUnion(
                            transformer_list=[
                                (
                                    "word_tfidf",
                                    TfidfVectorizer(ngram_range=(1, 2), max_features=6000, sublinear_tf=True),
                                ),
                                (
                                    "char_wb_tfidf",
                                    TfidfVectorizer(
                                        analyzer="char_wb",
                                        ngram_range=(2, 5),
                                        max_features=10000,
                                        sublinear_tf=True,
                                    ),
                                ),
                                (
                                    "char_raw_tfidf",
                                    TfidfVectorizer(
                                        analyzer="char",
                                        ngram_range=(2, 4),
                                        max_features=9000,
                                        sublinear_tf=True,
                                    ),
                                ),
                            ]
                        ),
                    ),
                    ("clf", LogisticRegression(max_iter=1200, class_weight="balanced")),
                ]
            )
            self.zh_semantic_risk_model.fit(texts, risk_labels)
        else:
            self.zh_semantic_risk_model = None

        if len(set(intent_labels)) >= 2:
            self.zh_semantic_intent_model = Pipeline(
                steps=[
                    (
                        "features",
                        FeatureUnion(
                            transformer_list=[
                                (
                                    "word_tfidf",
                                    TfidfVectorizer(ngram_range=(1, 2), max_features=7000, sublinear_tf=True),
                                ),
                                (
                                    "char_wb_tfidf",
                                    TfidfVectorizer(
                                        analyzer="char_wb",
                                        ngram_range=(2, 5),
                                        max_features=10000,
                                        sublinear_tf=True,
                                    ),
                                ),
                                (
                                    "char_raw_tfidf",
                                    TfidfVectorizer(
                                        analyzer="char",
                                        ngram_range=(2, 4),
                                        max_features=9000,
                                        sublinear_tf=True,
                                    ),
                                ),
                            ]
                        ),
                    ),
                    ("clf", LogisticRegression(max_iter=1200, class_weight="balanced")),
                ]
            )
            self.zh_semantic_intent_model.fit(texts, intent_labels)
        else:
            self.zh_semantic_intent_model = None

    def predict_chinese_semantic(
        self,
        user_input: str,
        scenario: str | None = None,
        direct_hints: list[str] | None = None,
    ) -> dict[str, Any] | None:
        if self.zh_semantic_risk_model is None and self.zh_semantic_intent_model is None:
            return None
        if not _contains_chinese_text(user_input):
            return None
        semantic_text = build_semantic_feature_text(
            user_input=user_input,
            scenario=scenario,
            direct_hints=direct_hints or extract_direct_instruction_hints(user_input),
        )
        risk_score = 0.0
        if self.zh_semantic_risk_model is not None:
            risk_score = float(self.zh_semantic_risk_model.predict_proba([semantic_text])[0][1])
        intent_label = None
        intent_confidence = 0.0
        if self.zh_semantic_intent_model is not None:
            intent_probabilities = self.zh_semantic_intent_model.predict_proba([semantic_text])[0]
            classes = list(self.zh_semantic_intent_model.named_steps["clf"].classes_)
            best_idx = int(intent_probabilities.argmax())
            intent_label = str(classes[best_idx])
            intent_confidence = float(intent_probabilities[best_idx])
        if "safe_meta_discussion" in semantic_text and intent_label == "benign_instructional":
            risk_score = min(risk_score, 0.35)
        return {
            "risk_score": round(risk_score, 4),
            "intent_label": intent_label,
            "intent_confidence": round(intent_confidence, 4),
        }

    def predict_label(self, text: str, threshold: float = 0.5) -> int:
        return int(self.predict_score(text) >= threshold)

    def evaluate(self, texts: list[str], labels: list[int], threshold: float = 0.5) -> dict[str, float]:
        predictions = [self.predict_label(text, threshold=threshold) for text in texts]
        return {
            "accuracy": float(accuracy_score(labels, predictions)),
            "precision": float(precision_score(labels, predictions, zero_division=0)),
            "recall": float(recall_score(labels, predictions, zero_division=0)),
            "f1": float(f1_score(labels, predictions, zero_division=0)),
        }


_CLASSIFIER: RiskClassifier | None = None


def get_classifier() -> RiskClassifier:
    global _CLASSIFIER
    if _CLASSIFIER is None:
        _CLASSIFIER = RiskClassifier()
    return _CLASSIFIER


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(8192), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _contains_chinese_text(text: str | None) -> bool:
    return bool(text and re.search(r"[\u4e00-\u9fff]", text))


def build_chinese_semantic_training_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    semantic_rows: list[dict[str, Any]] = []
    for row in rows:
        text = str(row.get("text") or "").strip()
        if not _contains_chinese_text(text):
            continue
        scenario = row.get("scenario")
        direct_hints = extract_direct_instruction_hints(text, row.get("retrieved_context"))
        attack_category = row.get("attack_category")
        attack_subtype = row.get("attack_subtype")
        sample_type = str(row.get("sample_type") or "").lower()
        is_positive = sample_type in {"attack", "adversarial"} or row.get("expected_result") in {"review", "block"}
        benign_instructional = bool(
            _CN_BENIGN_INSTRUCTIONAL_CONTEXT_PATTERN.search(text)
            or _BENIGN_PASSWORD_TOPIC_PATTERN.search(text)
            or (_BENIGN_DAN_REFERENCE_PATTERN.search(text) and _DAN_EXPLANATORY_CONTEXT_PATTERN.search(text))
            or _CN_HARMFUL_EXPLANATION_PATTERN.search(text)
            or _CN_ATTACK_RESEARCH_DISCUSSION_PATTERN.search(text)
            or re.search(r"(安全培训|风险讨论|研究报告|课程大纲|合规说明|反诈骗宣传|评估现有安全措施|文字冒险游戏|游戏剧情|虚拟世界)", text)
        )
        if is_positive and attack_category == "unsafe_prompt":
            risk_label = 1
            if attack_subtype == "exploit_or_attack_request":
                intent_label = "exploit"
            elif attack_subtype == "credential_or_data_theft":
                intent_label = "theft"
            elif attack_subtype == "phishing_or_fraud":
                intent_label = "fraud"
            elif attack_subtype == "malware_or_privilege_escalation":
                intent_label = "malware"
            elif attack_subtype == "security_bypass_or_evasion":
                intent_label = "evasion"
            else:
                intent_label = "operational_guidance"
            repeat = 3 if intent_label == "operational_guidance" else 2
        elif not is_positive and benign_instructional:
            risk_label = 0
            intent_label = "benign_instructional"
            repeat = 1
        else:
            continue
        semantic_item = {
            "semantic_text": build_semantic_feature_text(
                user_input=text,
                scenario=scenario,
                direct_hints=direct_hints,
            ),
            "risk_label": risk_label,
            "intent_label": intent_label,
        }
        for _ in range(repeat):
            semantic_rows.append(dict(semantic_item))
    return semantic_rows
