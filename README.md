## Hi this is a simple CA System

Request:

设计和实现一个CA系统，可以接受用户的认证请求，安全存储用户信息

记录储存对用户的一些认证信息，给用户颁发证书，可以吊销

接受用户的提交申请，提交时让用户自己产生公钥对

接受用户的申请，包括用户信息的表单提交，公钥的提交

在对用户实施认证的过程中，储存相应的电子文档，比如证书、营业执照的扫描文档

通过验证的给予颁发证书

用户密钥丢失时，可以吊销证书，密钥作废



CA_System/
├── ca_core.py          # 核心CA功能
├── main.py             # 图形界面
├── data/               # 数据目录
│   ├── issued/         # 已颁发证书
│   ├── revoked/        # 已吊销证书  
│   ├── users/          # 用户申请文件
│   ├── ca_cert.pem     # 根CA证书
│   ├── ca_key.pem      # 根CA私钥
│   ├── int_ca_cert.pem # 中间CA证书
│   ├── int_ca_key.pem  # 中间CA私钥
│   ├── crl.pem         # 证书吊销列表
│   └── ca.db           # SQLite数据库
└── logs/               # 日志目录


ca_core.py
 ├── init_ca()                    # 同时生成 Root + Intermediate CA
 ├── check_expiry_and_warn()      # 检查到期证书 
 ├── renew_certificate()          # 手动续签
 ├── auto_renew_all() 。          #自动续签
 ├── safe_basename() + safe_join() # 文件安全函数 
 ├── get_cert_details()           # 从数据库查 application_id
 ├── register_cert_in_db()        # 通过 approve_application 实现
 ├── 证书生命周期管理
 │   ├── submit_application()     # 提交申请
 │   ├── approve_application()    # 批准并颁发证书
 │   ├── reject_application()     # 拒绝申请
 │   └── revoke_application()     # 吊销证书
 ├── CA 基础设施
 │   ├── create_intermediate_ca() # 创建中间CA
 │   ├── _load_ca()              # 加载CA密钥
 │   └── generate_crl()          # 生成吊销列表
 ├── 列表查询功能
 │   ├── list_applications()     # 查询申请
 │   ├── list_issued_certs()     # 查询已颁发证书
 │   └── list_revoked_certs()    # 查询已吊销证书
 └── 数据库管理
     └── init_db()               # 初始化数据库

main.py
 ├── 主应用类 CAApp
 │   ├── 初始化函数
 │   │   ├── __init__()          # 初始化界面和连接
 │   │   └── startup_check_expiry() # 启动时检查到期证书
 │   ├── 核心操作处理函数
 │   │   ├── handle_init()       # 初始化CA处理
 │   │   ├── handle_new_app()    # 新建申请处理
 │   │   ├── handle_approve()    # 批准申请处理
 │   │   ├── handle_reject()     # 拒绝申请处理
 │   │   ├── handle_download_cert() # 下载证书处理
 │   │   ├── handle_renew_selected() # 手动续签处理
 │   │   ├── handle_auto_renew() # 自动续签处理
 │   │   └── handle_revoke_by_app_id() # 吊销证书处理
 │   ├── 列表刷新函数
 │   │   ├── refresh_pending_list()  # 刷新待审核列表
 │   │   ├── refresh_issued_list()   # 刷新已颁发列表
 │   │   └── refresh_revoked_list()  # 刷新已吊销列表
 │   ├── 详情显示函数
 │   │   ├── show_selected_application_details() # 显示申请详情
 │   │   ├── show_selected_cert_details()        # 显示证书详情
 │   │   └── show_selected_revoked_details()     # 显示吊销详情
 │   └── 工具函数
 │       └── log_msg()           # 日志记录
 ├── 对话框类 NewApplicationDialog
 │   ├── __init__()              # 初始化申请对话框
 │   ├── select_pubkey()         # 选择公钥文件
 │   ├── select_docs()           # 选择文档文件
 │   └── get_data()              # 获取申请数据
 └── 主程序入口
     └── if __name__ == "__main__" # 启动GUI应用


CA系统算法设计
├── 证书申请与签发
│   ├── 用户提交申请信息、公钥
│   ├── 管理员审核并生成X.509证书
│   ├── 中级CA签名证书
│   └── 写入数据库与日志
│
├── 证书吊销与作废
│   ├── 用户或管理员触发吊销请求
│   ├── 标记数据库 revoked=1
│   ├── 记录吊销时间 revoked_at
│   └── 验证时拒绝该证书
│
├── 证书续期与到期提醒
│   ├── 系统启动时扫描证书有效期
│   ├── 若距离到期<30天则提示
│   ├── 用户选择续期
│   └── 重新签发新证书并更新记录
│
├── 证书链与中级CA管理
│   ├── 系统启动检查中级CA存在性
│   ├── 无则由根CA签发新中级CA
│   ├── 用户证书由中级CA签发
│   └── 验证链：Root → Intermediate → User
│
└── 文件路径与安全防护
    ├── 使用basename清洗文件名
    ├── 路径限制到系统白名单目录
    ├── 检查是否包含“..”等非法符号
    └── 防止任意路径跳出与注入









