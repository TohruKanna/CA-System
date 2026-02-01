import sys
import os
import logging
import shutil
from typing import List, Dict, Any

from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QPushButton, QTextEdit,
    QInputDialog, QMessageBox, QListWidget, QLabel, QHBoxLayout,
    QFileDialog, QLineEdit, QFormLayout, QDialog, QDialogButtonBox,
    QTabWidget
)
from PyQt5.QtCore import Qt

import ca_core

# 日志设置
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_DIR = os.path.join(BASE_DIR, "logs")
os.makedirs(LOG_DIR, exist_ok=True)
LOG_FILE = os.path.join(LOG_DIR, "ca_activity.log")
logging.basicConfig(filename=LOG_FILE, level=logging.INFO, format="%(asctime)s - %(message)s")
logger = logging.getLogger("app")
logger.addHandler(logging.StreamHandler())


class NewApplicationDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("新建证书申请")
        self.setMinimumWidth(480)
        layout = QVBoxLayout()
        form = QFormLayout()

        self.name_input = QLineEdit()
        self.email_input = QLineEdit()
        self.pubkey_path_field = QLineEdit()
        self.pubkey_browse = QPushButton("选择公钥或 CSR 文件")
        self.pubkey_browse.clicked.connect(self.select_pubkey)

        self.docs_field = QLineEdit()
        self.docs_browse = QPushButton("选择扫描件（可多选）")
        self.docs_browse.clicked.connect(self.select_docs)

        form.addRow("姓名 (Name)：", self.name_input)
        form.addRow("邮箱 (Email)：", self.email_input)
        h1 = QHBoxLayout()
        h1.addWidget(self.pubkey_path_field)
        h1.addWidget(self.pubkey_browse)
        form.addRow("公钥 / CSR：", h1)
        h2 = QHBoxLayout()
        h2.addWidget(self.docs_field)
        h2.addWidget(self.docs_browse)
        form.addRow("扫描件 (营业执照等)：", h2)

        layout.addLayout(form)
        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        # 本地化按钮文本
        ok_btn = buttons.button(QDialogButtonBox.Ok)
        cancel_btn = buttons.button(QDialogButtonBox.Cancel)
        if ok_btn:
            ok_btn.setText("确定")
        if cancel_btn:
            cancel_btn.setText("取消")
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
        self.setLayout(layout)
        self.selected_docs: List[str] = []

    def select_pubkey(self):
        path, _ = QFileDialog.getOpenFileName(self, "选择公钥或 CSR 文件", "",
                                              "PEM 文件 (*.pem);;CSR 文件 (*.csr);;所有文件 (*)")
        if path:
            self.pubkey_path_field.setText(path)

    def select_docs(self):
        paths, _ = QFileDialog.getOpenFileNames(self, "选择扫描件", "", "所有文件 (*)")
        if paths:
            self.selected_docs = paths
            self.docs_field.setText("; ".join([os.path.basename(p) for p in paths]))

    def get_data(self) -> Dict[str, Any]:
        return {
            "name": self.name_input.text().strip(),
            "email": self.email_input.text().strip(),
            "pubkey_path": self.pubkey_path_field.text().strip(),
            "docs": self.selected_docs
        }


class CAApp(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("证书颁发系统（CA 桌面）")
        self.resize(1200, 700)
        main_layout = QHBoxLayout()

        left_layout = QVBoxLayout()
        right_layout = QVBoxLayout()

        # 左侧按钮区
        self.btn_init = QPushButton("初始化 CA")
        self.btn_new_app = QPushButton("提交新申请")
        self.btn_refresh_apps = QPushButton("刷新待审核列表")
        self.btn_approve = QPushButton("批准选中申请")
        self.btn_reject = QPushButton("拒绝选中申请")
        self.btn_refresh_certs = QPushButton("刷新已颁发证书")
        self.btn_download_cert = QPushButton("下载选中证书")
        self.btn_renew_selected = QPushButton("为选中证书续签")
        self.btn_auto_renew = QPushButton("自动续签所有临期证书")
        self.btn_revoke_selected = QPushButton("吊销（按申请ID）")
        #self.btn_view_revoked = QPushButton("查看已撤销证书")  # 新增按钮

        self.log = QTextEdit()
        self.log.setReadOnly(True)
        self.log.setFixedHeight(200)

        left_layout.addWidget(self.btn_init)
        left_layout.addWidget(self.btn_new_app)
        left_layout.addWidget(self.btn_refresh_apps)
        left_layout.addWidget(self.btn_approve)
        left_layout.addWidget(self.btn_reject)
        left_layout.addSpacing(6)
        left_layout.addWidget(self.btn_refresh_certs)
        left_layout.addWidget(self.btn_download_cert)
        left_layout.addWidget(self.btn_renew_selected)
        left_layout.addWidget(self.btn_auto_renew)
        left_layout.addWidget(self.btn_revoke_selected)
        left_layout.addSpacing(6)
        #left_layout.addWidget(self.btn_view_revoked)  # 新增按钮
        left_layout.addWidget(QLabel("操作日志"))
        left_layout.addWidget(self.log)

        # 右侧内容区 - 使用标签页
        self.tabs = QTabWidget()

        # 待审核申请标签页
        self.pending_tab = QWidget()
        pending_layout = QVBoxLayout()
        self.pending_list = QListWidget()
        pending_layout.addWidget(QLabel("待审核申请 (Pending)"))
        pending_layout.addWidget(self.pending_list)
        self.pending_tab.setLayout(pending_layout)

        # 已颁发证书标签页
        self.issued_tab = QWidget()
        issued_layout = QVBoxLayout()
        self.issued_list = QListWidget()
        issued_layout.addWidget(QLabel("已颁发证书 (Issued)"))
        issued_layout.addWidget(self.issued_list)
        self.issued_tab.setLayout(issued_layout)

        # 已撤销证书标签页
        self.revoked_tab = QWidget()
        revoked_layout = QVBoxLayout()
        self.revoked_list = QListWidget()
        revoked_layout.addWidget(QLabel("已撤销证书 (Revoked)"))
        revoked_layout.addWidget(self.revoked_list)
        self.revoked_tab.setLayout(revoked_layout)

        # 详细信息区域
        self.details = QTextEdit()
        self.details.setReadOnly(True)

        # 添加标签页
        self.tabs.addTab(self.pending_tab, "待审核")
        self.tabs.addTab(self.issued_tab, "已颁发")
        self.tabs.addTab(self.revoked_tab, "已撤销")

        right_layout.addWidget(self.tabs)
        right_layout.addWidget(QLabel("详细信息 (Details)"))
        right_layout.addWidget(self.details)

        main_layout.addLayout(left_layout, stretch=1)
        main_layout.addLayout(right_layout, stretch=2)
        self.setLayout(main_layout)

        # 连接信号
        self.btn_init.clicked.connect(self.handle_init)
        self.btn_new_app.clicked.connect(self.handle_new_app)
        self.btn_refresh_apps.clicked.connect(self.refresh_pending_list)
        self.btn_approve.clicked.connect(self.handle_approve)
        self.btn_reject.clicked.connect(self.handle_reject)
        self.btn_refresh_certs.clicked.connect(self.refresh_issued_list)
        self.btn_download_cert.clicked.connect(self.handle_download_cert)
        self.btn_renew_selected.clicked.connect(self.handle_renew_selected)
        self.btn_auto_renew.clicked.connect(self.handle_auto_renew)
        #self.btn_view_revoked.clicked.connect(self.refresh_revoked_list)  # 新增连接
        self.pending_list.itemSelectionChanged.connect(self.show_selected_application_details)
        self.issued_list.itemSelectionChanged.connect(self.show_selected_cert_details)
        self.revoked_list.itemSelectionChanged.connect(self.show_selected_revoked_details)  # 新增连接
        self.btn_revoke_selected.clicked.connect(self.handle_revoke_by_app_id)

        # 启动日志与到期检测
        self.log_msg("系统已启动。")
        self.startup_check_expiry()
        # 刷新列表
        self.refresh_pending_list()
        self.refresh_issued_list()
        self.refresh_revoked_list()  # 新增：启动时刷新撤销列表

    def log_msg(self, msg: str):
        self.log.append(msg)
        logger.info(msg)

    def startup_check_expiry(self):
        """启动时检查临期证书并提醒（优先调用 ca_core.check_expiry_and_warn）"""
        try:
            warn_list = []
            if hasattr(ca_core, "check_expiry_and_warn"):
                warn_list = ca_core.check_expiry_and_warn(days_before=30)
            elif hasattr(ca_core, "check_expiring_certs"):
                # older name
                tmp = ca_core.check_expiring_certs(days=30)
                # tmp may be list of tuples (app_id, path, end)
                warn_list = []
                for row in tmp:
                    if isinstance(row, tuple) and len(row) >= 3:
                        warn_list.append({
                            "application_id": row[0],
                            "filename": os.path.basename(row[1]),
                            "not_after": row[2].isoformat() if hasattr(row[2], "isoformat") else str(row[2]),
                        })
            else:
                self.log_msg("ca_core 未提供到期检查函数 (check_expiry_and_warn 或 check_expiring_certs)。")
                return

            if warn_list:
                lines = ["以下证书将在 30 天内到期："]
                for e in warn_list:
                    aid = e.get("application_id") or "未知"
                    fname = e.get("filename") or e.get("path") or "未知文件"
                    na = e.get("not_after") or "未知"
                    lines.append(f"申请ID={aid}  文件={fname}  到期日={na}")
                QMessageBox.warning(self, "到期提醒", "\n".join(lines))
                self.log_msg("到期提醒：\n" + "\n".join(lines))
            else:
                self.log_msg("未发现 30 天内到期的证书。")
        except Exception as ex:
            self.log_msg(f"启动到期检测失败: {ex}")

    # ---------- GUI 操作实现 ----------
    def handle_init(self):
        nm, ok = QInputDialog.getText(self, "初始化 CA", "请输入 CA 名称：", text="My Root CA")
        if not ok:
            return
        try:
            res = ca_core.init_ca(nm.strip() or "My Root CA")
            self.log_msg(str(res))
            QMessageBox.information(self, "初始化", str(res))
            # 若存在创建中级 CA 的函数则尝试调用
            if hasattr(ca_core, "create_intermediate_ca"):
                try:
                    ird = ca_core.create_intermediate_ca()
                    self.log_msg(f"create_intermediate_ca: {ird}")
                except Exception as e:
                    self.log_msg(f"create_intermediate_ca 失败: {e}")
            # 尝试生成 CRL（如果有此函数）
            if hasattr(ca_core, "generate_crl"):
                try:
                    ca_core.generate_crl()
                except Exception:
                    pass
            self.refresh_pending_list()
            self.refresh_issued_list()
            self.refresh_revoked_list()  # 新增：刷新撤销列表
        except Exception as e:
            self.log_msg(f"初始化失败: {e}")
            QMessageBox.critical(self, "错误", str(e))

    def handle_new_app(self):
        dlg = NewApplicationDialog(self)
        if dlg.exec_() != QDialog.Accepted:
            return
        data = dlg.get_data()
        if not data['name'] or not data['pubkey_path']:
            QMessageBox.warning(self, "警告", "姓名和公钥/CSR 为必填项。")
            return
        try:
            app_id = ca_core.submit_application(data['name'], data['email'], data['pubkey_path'], data['docs'])
            self.log_msg(f"已提交申请 {app_id} - 用户：{data['name']}")
            QMessageBox.information(self, "提交成功", f"申请已提交（ID={app_id}）")
            self.refresh_pending_list()
        except Exception as e:
            self.log_msg(f"提交失败: {e}")
            QMessageBox.critical(self, "错误", str(e))

    def refresh_pending_list(self):
        self.pending_list.clear()
        try:
            apps = ca_core.list_applications(status="pending")
        except Exception:
            # fallback: try list_applications without args
            apps = ca_core.list_applications()
        if not apps:
            self.pending_list.addItem("【空】暂无待审核申请")
            return
        for app in apps:
            txt = f"ID={app.get('id')}  姓名：{app.get('name')}  （{app.get('email')}）"
            self.pending_list.addItem(txt)
            item = self.pending_list.item(self.pending_list.count() - 1)
            # 保存 app id 为 UserRole 数据
            item.setData(Qt.UserRole, app.get('id'))

    def refresh_issued_list(self):
        self.issued_list.clear()
        try:
            certs = ca_core.list_issued_certs()
        except Exception:
            # try alternative name in ca_core (list certificates)
            if hasattr(ca_core, "list_certificates"):
                certs = ca_core.list_certificates()
            else:
                certs = []
        if not certs:
            self.issued_list.addItem("【空】暂无已颁发证书")
            return
        for cert in certs:
            filename = cert.get('filename') or os.path.basename(cert.get('path', 'unknown'))
            cn = cert.get('common_name') or ""
            not_before = cert.get('not_before') or ""
            not_after = cert.get('not_after') or ""
            txt = f"{filename}  CN={cn}  有效期：{not_before} -> {not_after}"
            self.issued_list.addItem(txt)
            item = self.issued_list.item(self.issued_list.count() - 1)
            item.setData(Qt.UserRole, cert.get('path'))

    def refresh_revoked_list(self):
        """刷新已撤销证书列表"""
        self.revoked_list.clear()
        try:
            # 尝试调用新的 list_revoked_certs 函数
            if hasattr(ca_core, "list_revoked_certs"):
                revoked_certs = ca_core.list_revoked_certs()
            else:
                # 回退方案：从数据库获取已撤销的申请
                revoked_apps = ca_core.list_applications(status="revoked")
                revoked_certs = []
                for app in revoked_apps:
                    revoked_certs.append({
                        'application_id': app.get('id', '未知'),
                        'name': app.get('name', '未知'),
                        'filename': os.path.basename(app.get('cert_path', '')) if app.get('cert_path') else "未知文件",
                        'revoked_at': app.get('revoked_at', '未知'),
                        'revoke_reason': app.get('revoke_reason', '未知')
                    })
        except Exception as e:
            self.log_msg(f"获取撤销证书列表失败: {e}")
            revoked_certs = []

        if not revoked_certs:
            self.revoked_list.addItem("【空】暂无已撤销证书")
            return

        for cert in revoked_certs:
            app_id = cert.get('application_id', '未知')
            name = cert.get('name', '未知')
            filename = cert.get('filename', '未知')
            revoked_at = cert.get('revoked_at', '未知')
            reason = cert.get('revoke_reason', '未知')

            # 简化显示的时间格式
            try:
                revoked_time = revoked_at.split('T')[0] if 'T' in revoked_at else revoked_at
            except:
                revoked_time = revoked_at

            txt = f"ID={app_id}  {name}  文件：{filename}  撤销时间：{revoked_time}"
            self.revoked_list.addItem(txt)
            item = self.revoked_list.item(self.revoked_list.count() - 1)
            item.setData(Qt.UserRole, cert)

    def show_selected_application_details(self):
        items = self.pending_list.selectedItems()
        if not items:
            self.details.clear()
            return
        app_id = items[0].data(Qt.UserRole)
        try:
            apps = ca_core.list_applications()
        except Exception:
            apps = []
        selected = None
        for a in apps:
            if a.get('id') == app_id:
                selected = a
                break
        if not selected:
            self.details.setPlainText("无详细信息。")
            return
        lines = [
            f"申请ID：{selected.get('id')}",
            f"姓名：{selected.get('name')}",
            f"邮箱：{selected.get('email')}",
            f"状态：{selected.get('status')}",
            f"创建时间：{selected.get('created_at')}",
            f"公钥文件：{selected.get('pubkey_path')}",
            "附加文件：",
        ]
        for d in selected.get('docs', []) if isinstance(selected.get('docs', []), list) else []:
            lines.append(f"  - {d}")
        self.details.setPlainText("\n".join(lines))

    def show_selected_cert_details(self):
        items = self.issued_list.selectedItems()
        if not items:
            self.details.clear()
            return
        cert_path = items[0].data(Qt.UserRole)
        if not cert_path or not os.path.exists(cert_path):
            self.details.setPlainText("未找到证书文件。")
            return
        try:
            d = ca_core.get_cert_details(cert_path)
            app_id = d.get("application_id", "未知")
            text_lines = [
                f"申请ID：{app_id}",
                f"文件名：{d.get('filename')}",
                f"主题：{d.get('subject')}",
                f"颁发者：{d.get('issuer')}",
                f"序列号：{d.get('serial_number')}",
                f"有效期自：{d.get('not_valid_before')}",
                f"有效期至：{d.get('not_valid_after')}",
                "扩展信息：",
            ]
            for ext in d.get("extensions", []):
                text_lines.append(f"  - {ext}")
            self.details.setPlainText("\n".join(text_lines))
        except Exception as e:
            self.details.setPlainText(f"解析失败：{e}")
            self.log_msg(f"解析证书失败: {e}")

    def show_selected_revoked_details(self):
        """显示选中的已撤销证书的详细信息"""
        items = self.revoked_list.selectedItems()
        if not items:
            self.details.clear()
            return

        cert_info = items[0].data(Qt.UserRole)
        if not cert_info:
            self.details.setPlainText("无详细信息。")
            return

        lines = [
            f"申请ID：{cert_info.get('application_id', '未知')}",
            f"姓名：{cert_info.get('name', '未知')}",
            f"证书文件：{cert_info.get('filename', '未知')}",
            f"撤销时间：{cert_info.get('revoked_at', '未知')}",
            f"撤销原因：{cert_info.get('revoke_reason', '未知')}",
        ]

        # 如果序列号存在，也显示
        if cert_info.get('serial_number'):
            lines.append(f"序列号：{cert_info.get('serial_number')}")

        # 尝试获取更多证书详细信息
        try:
            app_id = cert_info.get('application_id')
            if app_id and app_id != '未知' and hasattr(ca_core, "get_revoked_cert_details"):
                revoked_details = ca_core.get_revoked_cert_details(int(app_id))
                if revoked_details:
                    if revoked_details.get('subject'):
                        lines.append(f"原主题：{revoked_details.get('subject')}")
                    if revoked_details.get('serial_number'):
                        lines.append(f"原序列号：{revoked_details.get('serial_number')}")
                    if revoked_details.get('not_valid_before') and revoked_details.get('not_valid_after'):
                        lines.append(
                            f"原有效期：{revoked_details.get('not_valid_before')} 至 {revoked_details.get('not_valid_after')}")
        except Exception as e:
            self.log_msg(f"获取撤销证书详情失败: {e}")

        self.details.setPlainText("\n".join(lines))

    def handle_approve(self):
        items = self.pending_list.selectedItems()
        if not items:
            QMessageBox.information(self, "提示", "请先选择要批准的申请。")
            return
        app_id = items[0].data(Qt.UserRole)
        try:
            res = ca_core.approve_application(app_id)
            self.log_msg(f"已批准申请 {app_id} -> 证书路径：{res.get('cert_path')}")
            QMessageBox.information(self, "批准成功", f"已签发证书：\n{res.get('cert_path')}")
            # 可能生成 CRL
            if hasattr(ca_core, "generate_crl"):
                try:
                    ca_core.generate_crl()
                except Exception:
                    pass
            self.refresh_pending_list()
            self.refresh_issued_list()
            self.refresh_revoked_list()  # 新增：刷新撤销列表
        except Exception as e:
            self.log_msg(f"批准失败: {e}")
            QMessageBox.critical(self, "错误", f"批准失败: {e}")

    def handle_reject(self):
        items = self.pending_list.selectedItems()
        if not items:
            QMessageBox.information(self, "提示", "请先选择要拒绝的申请。")
            return
        app_id = items[0].data(Qt.UserRole)
        reason, ok = QInputDialog.getText(self, "拒绝申请", "请输入拒绝原因：")
        if not ok:
            return
        try:
            ca_core.reject_application(app_id, reason)
            self.log_msg(f"已拒绝申请 {app_id}：{reason}")
            QMessageBox.information(self, "已拒绝", f"申请 {app_id} 已被拒绝。")
            self.refresh_pending_list()
        except Exception as e:
            self.log_msg(f"拒绝失败: {e}")
            QMessageBox.critical(self, "错误", str(e))

    def handle_download_cert(self):
        items = self.issued_list.selectedItems()
        if not items:
            QMessageBox.information(self, "提示", "请先选择要下载的证书。")
            return

        cert_path = items[0].data(Qt.UserRole)
        if not cert_path or not os.path.exists(cert_path):
            QMessageBox.warning(self, "错误", "证书文件不存在。")
            return

        save_path, _ = QFileDialog.getSaveFileName(
            self,
            "保存证书",
            os.path.basename(cert_path),
            "PEM 文件 (*.pem);;所有文件 (*)"
        )

        if not save_path:
            return  # 用户取消

        try:
            shutil.copy(cert_path, save_path)
            self.log_msg(f"已下载证书到 {save_path}")
            QMessageBox.information(self, "下载成功", f"证书已保存到：\n{save_path}")
        except Exception as e:
            self.log_msg(f"下载失败: {e}")
            QMessageBox.critical(self, "下载失败", str(e))

    def handle_renew_selected(self):
        items = self.issued_list.selectedItems()
        if not items:
            QMessageBox.information(self, "提示", "请先选择要续签的证书。")
            return
        cert_path = items[0].data(Qt.UserRole)
        try:
            details = ca_core.get_cert_details(cert_path)
            app_id = details.get("application_id")
            if not app_id:
                QMessageBox.warning(self, "错误", "无法找到对应的申请 ID，无法续签。")
                return
            conf = QMessageBox.question(self, "确认续签", f"确认为申请 ID={app_id} 续签证书？",
                                        QMessageBox.Yes | QMessageBox.No)
            if conf != QMessageBox.Yes:
                return
            if hasattr(ca_core, "renew_certificate"):
                res = ca_core.renew_certificate(int(app_id))
                self.log_msg(f"已为申请 {app_id} 续签 -> {res.get('cert_path')}")
                QMessageBox.information(self, "续签成功", f"续签成功：\n{res.get('cert_path')}")
                self.refresh_pending_list()
                self.refresh_issued_list()
                self.refresh_revoked_list()  # 新增：刷新撤销列表
            else:
                QMessageBox.warning(self, "不支持", "当前 ca_core 未实现 renew_certificate 功能。")
        except Exception as e:
            self.log_msg(f"续签失败: {e}")
            QMessageBox.critical(self, "续签失败", str(e))

    def handle_auto_renew(self):
        if not hasattr(ca_core, "auto_renew_all"):
            QMessageBox.warning(self, "不支持", "当前 ca_core 未实现自动续签功能 (auto_renew_all)。")
            return
        conf = QMessageBox.question(self, "自动续签", "确认对所有临期证书执行自动续签操作？",
                                    QMessageBox.Yes | QMessageBox.No)
        if conf != QMessageBox.Yes:
            return
        try:
            renewed = ca_core.auto_renew_all()
            self.log_msg(f"自动续签完成，续签的申请：{renewed}")
            QMessageBox.information(self, "自动续签完成", f"已对以下申请执行续签：\n{renewed}")
            self.refresh_issued_list()
            self.refresh_revoked_list()  # 新增：刷新撤销列表
        except Exception as e:
            self.log_msg(f"自动续签失败: {e}")
            QMessageBox.critical(self, "自动续签失败", str(e))

    def handle_revoke_by_app_id(self):
        text, ok = QInputDialog.getText(self, "吊销申请", "请输入要吊销的申请 ID：")
        if not ok:
            return
        try:
            app_id = int(text.strip())
        except Exception:
            QMessageBox.warning(self, "输入错误", "申请 ID 无效。")
            return
        reason, ok2 = QInputDialog.getText(self, "吊销原因", "请输入吊销原因（可选）：", text="密钥泄露")
        if not ok2:
            return
        try:
            res = ca_core.revoke_application(app_id, reason or "密钥泄露")
            self.log_msg(f"吊销结果: {res}")
            QMessageBox.information(self, "吊销成功", str(res))
            self.refresh_pending_list()
            self.refresh_issued_list()
            self.refresh_revoked_list()  # 新增：刷新撤销列表
        except Exception as e:
            self.log_msg(f"吊销失败: {e}")
            QMessageBox.critical(self, "错误", str(e))


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = CAApp()
    window.show()
    sys.exit(app.exec_())