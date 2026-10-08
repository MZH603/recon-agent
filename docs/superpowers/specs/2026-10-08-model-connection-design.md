# 模型连接配置设计

用户要求模型配置同时支持 API 请求地址和 API Key，提高自定义端点灵活度。本变更只修正模型连接配置，不扩展会话编排。

- 在 ModelConfig 提供 api_base、api_key、api_key_env；api_base 为 SDK 的 API 根地址，包含 /v1 时保留，不要求用户填写具体 /chat/completions 路径。
- 非空 api_key 优先于指定环境变量；未配置直接 Key 时沿用 api_key_env，二者均未指定时继续由 LiteLLM 原有环境变量解析。指定环境变量缺失且没有直接 Key 时仍明确报错/跳过，不悄悄用另一份凭据。
- 直接 Key 使用 SecretStr，排除于主模型及 ModelSpec 的摘要序列化；端点字典里的直接 Key 也需要隐藏。适配器仅构造 SDK 请求时读取明文，不加入日志、会话或报告。
- 保留 custom_endpoints 的 name/model/base_url/api_key_env 结构，并增加直接 api_key，允许 api_base 作为 base_url 的同义配置。选中的命名端点拥有自己的连接参数，不继承默认 Key。
- 默认模型及 CLI --model 未匹配命名端点时使用主配置连接。fallback 显式使用各自端点或供应商默认连接，不能继承主模型 URL/Key，避免跨供应商误发凭据。
- OpenAI 兼容代理或自定义模型使用 openai/模型名，模型前缀由 LiteLLM 决定协议；provider: litellm 保持为现有适配层选择。
- config.yaml 展示默认 API 根地址、空 Key 和可选环境变量名；不写入真实 Key。README/使用说明书展示 YAML 示例和优先级，并修正相关“Key 只走环境变量”的旧表述。

备选方案：只增加地址环境变量改动较小但配置分散；仅使用 custom_endpoints 已可表达地址但主配置不直观。采用直接主配置加旧端点兼容，不增加 UI/命令行凭据参数。

验收：真实 Settings.load YAML → resolve_model/build_provider → LiteLLMAdapter → 假 SDK 收到准确地址与 Key；直接/环境变量优先级、旧端点兼容、CLI override、fallback 连接隔离、摘要 Key 隐藏；完整离线回归，不向外部 API 发请求。
