# -*- coding: utf-8 -*-

import sys
import json
import os
import time
import traceback
import random
import datetime
import hashlib
import base64
import threading
from typing import List, Dict, Any
from dataclasses import dataclass, field, asdict
from enum import Enum

import requests
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                             QHBoxLayout, QTextEdit, QLineEdit, QPushButton, 
                             QLabel, QScrollArea, QFrame, QMessageBox,
                             QSizePolicy, QFileDialog, QScrollBar, QDialog,
                             QCheckBox)
from PyQt5.QtCore import Qt, QTimer, pyqtSignal, QThread, QSize, QMetaObject
from PyQt5.QtGui import QColor, QFont, QTextCursor, QTextOption, QIcon
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

# ==================== AES加密辅助类 ====================

class AESHelper:
    """AES加密辅助类"""
    
    def __init__(self, key):
        """初始化AES加密器
        
        Args:
            key: 加密密钥，将使用SHA256哈希生成32字节密钥
        """
        # 使用SHA256生成32字节密钥
        from hashlib import sha256
        self.key = sha256(key.encode('utf-8')).digest()
    
    def encrypt(self, plaintext):
        """加密文本
        
        Args:
            plaintext: 明文文本
            
        Returns:
            包含IV和密文的base64编码字符串
        """
        # 生成随机IV
        iv = get_random_bytes(AES.block_size)
        
        # 创建AES加密器
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        
        # 加密数据
        ciphertext = cipher.encrypt(pad(plaintext.encode('utf-8'), AES.block_size))
        
        # 返回IV+密文的base64编码
        return base64.b64encode(iv + ciphertext).decode('utf-8')
    
    def decrypt(self, encrypted_text):
        """解密文本
        
        Args:
            encrypted_text: 包含IV和密文的base64编码字符串
            
        Returns:
            解密后的明文文本
        """
        try:
            # 解码base64
            data = base64.b64decode(encrypted_text)
            
            # 提取IV和密文
            iv = data[:AES.block_size]
            ciphertext = data[AES.block_size:]
            
            # 创建AES解密器
            cipher = AES.new(self.key, AES.MODE_CBC, iv)
            
            # 解密并去除填充
            plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
            
            return plaintext.decode('utf-8')
        except Exception as e:
            print(f"解密失败: {e}")
            return ""

# ==================== API密钥设置对话框 ====================

class ApiKeyDialog(QDialog):
    """API密钥设置对话框"""
    
    def __init__(self, parent=None, current_key=""):
        super().__init__(parent)
        self.setWindowTitle("设置API密钥")
        self.setModal(True)
        self.setFixedSize(400, 230)
        
        # 创建布局
        layout = QVBoxLayout(self)
        
        # 说明标签
        self.info_label = QLabel("请输入智谱AI API密钥:")
        layout.addWidget(self.info_label)
        
        # 创建API密钥输入框的布局
        api_key_layout = QHBoxLayout()
        
        # API密钥输入框
        self.api_key_input = QLineEdit()
        self.api_key_input.setPlaceholderText("在此输入您的API密钥")
        self.api_key_input.setText(current_key)
        self.api_key_input.setEchoMode(QLineEdit.Password)  # 设置为密码模式
        
        # 新增：创建🙈按钮
        self.show_password_button = QPushButton("🙈")
        self.show_password_button.setFixedSize(50, 40)
        self.show_password_button.setToolTip("显示/隐藏密码")
        self.show_password_button.clicked.connect(self.toggle_password_visibility)
        
        api_key_layout.addWidget(self.api_key_input)
        api_key_layout.addWidget(self.show_password_button)
        
        layout.addLayout(api_key_layout)
        
        # 获取API密钥的链接
        link_label = QLabel('还没有API密钥？<a href="https://open.bigmodel.cn/usercenter/apikeys">点击这里获取</a>')
        link_label.setOpenExternalLinks(True)
        layout.addWidget(link_label)
        
        # 状态标签
        self.status_label = QLabel("")
        self.status_label.setStyleSheet("color: red;")
        layout.addWidget(self.status_label)
        
        # 按钮布局
        button_layout = QHBoxLayout()
        
        self.test_button = QPushButton("测试连接")
        self.test_button.clicked.connect(self.test_api_key)
        button_layout.addWidget(self.test_button)
        
        button_layout.addStretch()
        
        self.later_button = QPushButton("稍后设置")
        self.later_button.clicked.connect(lambda: self.done(1))
        button_layout.addWidget(self.later_button)
        
        self.ok_button = QPushButton("完成")
        self.ok_button.clicked.connect(lambda: self.done(0))
        button_layout.addWidget(self.ok_button)
        
        layout.addLayout(button_layout)
        
        # 设置焦点
        if not current_key:
            self.api_key_input.setFocus()
        
        # 标记当前密码可见性状态
        self.password_visible = False

    def toggle_password_visibility(self):
        """切换密码可见性 - 动漫风格"""
        if self.password_visible:
            self.api_key_input.setEchoMode(QLineEdit.Password)
            self.show_password_button.setText("🙈")  # 闭眼
            self.password_visible = False
        else:
            self.api_key_input.setEchoMode(QLineEdit.Normal)
            self.show_password_button.setText("👀")  # 睁眼
            self.password_visible = True
        
    def get_api_key(self):
        """获取API密钥"""
        return self.api_key_input.text().strip()
    
    def test_api_key(self):
        """测试API密钥是否有效"""
        api_key = self.get_api_key()
        if not api_key:
            self.status_label.setText("请输入API密钥")
            return
        
        self.status_label.setText("测试连接中...")
        self.test_button.setEnabled(False)
        self.repaint()  # 强制重绘以显示状态
        
        # 在新线程中测试连接
        def test_connection():
            try:
                headers = {
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {api_key}"
                }
                
                data = {
                    "model": "glm-4-flash",
                    "messages": [{"role": "user", "content": "测试连接，请回复'连接成功'"}],
                    "stream": False
                }
                
                response = requests.post(
                    "https://open.bigmodel.cn/api/paas/v4/chat/completions",
                    headers=headers,
                    json=data,
                    timeout=10
                )
                
                if response.status_code == 200:
                    self.status_label.setText("连接成功！")
                    self.status_label.setStyleSheet("color: green;")
                else:
                    self.status_label.setText(f"连接失败: {response.status_code}")
                    self.status_label.setStyleSheet("color: red;")
                    
            except Exception as e:
                self.status_label.setText(f"连接错误: {str(e)}")
                self.status_label.setStyleSheet("color: red;")
            
            self.test_button.setEnabled(True)
        
        # 在新线程中执行测试
        thread = threading.Thread(target=test_connection)
        thread.daemon = True
        thread.start()

# ==================== 配置和数据结构 ====================

# 不再使用硬编码的API_KEY
# API_KEY = "e7509fc557394a619bc89d9bc44172ce.qY4uSyCofHoCfQSX"
API_URL = "https://open.bigmodel.cn/api/paas/v4/chat/completions"

@dataclass
class Message:
    """消息数据类"""
    agent: str  # "Agent_A" 或 "Agent_B"
    content: str
    timestamp: float = field(default_factory=time.time)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "agent": self.agent,
            "content": self.content,
            "timestamp": self.timestamp
        }

class AgentType(Enum):
    """代理类型枚举"""
    AGENT_A = "Agent_A"
    AGENT_B = "Agent_B"

# ==================== API 调用线程 ====================

class APIWorker(QThread):
    """API调用工作线程 - 非流式版本"""
    response_complete = pyqtSignal(str, str)  # 代理类型, 完整内容
    error_occurred = pyqtSignal(str)  # 错误信息
    timeout_occurred = pyqtSignal()  # 超时信号
    
    def __init__(self, api_key: str, api_url: str, agent_type: AgentType, 
                 messages: List[Dict], system_prompt: str):
        super().__init__()
        self.api_key = api_key
        self.api_url = api_url
        self.agent_type = agent_type
        self.messages = messages
        self.system_prompt = system_prompt
        self.stop_requested = False
        self.timeout_seconds = 30
        
    def run(self):
        """执行API调用（非流式）"""
        try:
            headers = {
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json"
            }
            
            # 构建请求数据 - 非流式
            request_data = {
                "model": "glm-4-flash",
                "messages": self.messages,
                "max_tokens": 150,
                "temperature": 0.7,
                "stream": False  # 改为非流式
            }
            
            start_time = time.time()
            
            try:
                response = requests.post(
                    self.api_url,
                    headers=headers,
                    json=request_data,
                    timeout=self.timeout_seconds
                )
                
                # 检查HTTP状态码
                if response.status_code != 200:
                    error_detail = response.text
                    try:
                        error_json = json.loads(error_detail)
                        error_msg = error_json.get("error", {}).get("message", error_detail)
                    except:
                        error_msg = error_detail
                    
                    self.error_occurred.emit(f"API错误 {response.status_code}: {error_msg}")
                    return
                
            except requests.exceptions.Timeout:
                self.timeout_occurred.emit()
                return
            except requests.exceptions.RequestException as e:
                self.error_occurred.emit(f"网络请求错误: {str(e)}")
                return
            
            # 处理非流式响应
            try:
                response_data = response.json()
                choices = response_data.get("choices", [])
                if choices:
                    message = choices[0].get("message", {})
                    content = message.get("content", "")
                    if content:
                        self.response_complete.emit(
                            self.agent_type.value, 
                            content
                        )
                    else:
                        self.error_occurred.emit("API返回了空内容")
                else:
                    self.error_occurred.emit("API返回了无效的响应格式")
                    
            except json.JSONDecodeError as e:
                self.error_occurred.emit(f"JSON解析错误: {str(e)}")
            except Exception as e:
                self.error_occurred.emit(f"响应处理错误: {str(e)}")
                
        except Exception as e:
            if not self.stop_requested:
                error_msg = f"API调用错误: {str(e)}"
                self.error_occurred.emit(error_msg)
    
    def stop(self):
        """停止API调用"""
        self.stop_requested = True

# ==================== 聊天气泡控件 ====================

class ChatBubble(QFrame):
    """聊天气泡控件 - 优化版：无高度限制，完全显示文本"""
    
    def __init__(self, agent_name: str, is_right: bool = True):
        super().__init__()
        self.agent_name = agent_name
        self.is_right = is_right
        self.full_content = ""
        self.init_ui()
        
    def init_ui(self):
        """初始化UI"""
        self.setFrameStyle(QFrame.StyledPanel | QFrame.Raised)
        self.setLineWidth(1)
        
        if self.is_right:
            bg_color = QColor(220, 240, 255)  # 浅蓝色，代理A
            align = Qt.AlignRight
        else:
            bg_color = QColor(220, 255, 220)  # 浅绿色，代理B
            align = Qt.AlignLeft
            
        self.setStyleSheet(f"""
            QFrame {{
                background-color: {bg_color.name()};
                border-radius: 10px;
                padding: 10px;
                margin: 5px;
            }}
        """)
        
        layout = QVBoxLayout()
        
        # 代理名称标签
        self.name_label = QLabel(self.agent_name)
        self.name_label.setFont(QFont("Arial", 10, QFont.Bold))
        self.name_label.setAlignment(align)
        layout.addWidget(self.name_label)
        
        # 内容文本编辑框 - 优化：无高度限制，无滚动条
        self.content_text = QTextEdit()
        self.content_text.setReadOnly(True)
        # 移除高度限制
        self.content_text.setMinimumHeight(20)
        self.content_text.setMaximumHeight(16777215)  # 非常大的值，相当于无限制
        # 设置字体
        self.content_text.setFont(QFont("Arial", 10))
        # 移除边框和背景
        self.content_text.setStyleSheet("""
            QTextEdit {
                background-color: transparent;
                border: none;
            }
        """)
        # 设置自动换行
        self.content_text.setWordWrapMode(QTextOption.WrapAtWordBoundaryOrAnywhere)
        # 禁用垂直滚动条
        self.content_text.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        # 禁用水平滚动条
        self.content_text.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        # 启用自适应高度
        self.content_text.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)
        
        layout.addWidget(self.content_text)
        
        self.setLayout(layout)
    
    def set_complete_content(self, content: str):
        """设置完整内容"""
        self.full_content = content
        self.content_text.setPlainText(content)
        
        # 调整文本编辑框高度以适应内容
        self.adjust_text_edit_height()
        
        # 滚动到底部
        cursor = self.content_text.textCursor()
        cursor.movePosition(QTextCursor.End)
        self.content_text.setTextCursor(cursor)
    
    def adjust_text_edit_height(self):
        """根据内容调整文本编辑框高度"""
        # 获取文档的理想高度
        doc_height = self.content_text.document().size().height()
        
        # 加上一些边距
        new_height = int(doc_height) + 20
        
        # 设置新的高度
        self.content_text.setMinimumHeight(new_height)
        self.content_text.setMaximumHeight(new_height)
        
        # 更新气泡自身的高度
        self.adjustSize()
    
    def clear(self):
        """清空气泡内容"""
        self.full_content = ""
        self.content_text.clear()
        self.content_text.setMinimumHeight(20)
        self.content_text.setMaximumHeight(16777215)

# ==================== 主窗口 ====================

class MainWindow(QMainWindow):
    """主窗口"""
    
    def __init__(self):
        super().__init__()
        # 初始化AES加密器
        self.aes_helper = AESHelper("zy142857")
        
        # 加载API密钥配置
        self.api_key = self.load_api_key()
        self.api_url = API_URL
        self.theme = ""
        self.conversation_active = False
        self.current_agent = AgentType.AGENT_A
        self.retry_count = 0
        self.max_retries = 2
        
        # 如果没有API密钥或密钥无效，提示用户设置
        if not self.api_key or not self.test_api_key(self.api_key):
            self.show_api_key_dialog()
        
        # 存储对话历史
        self.conversation_history_a: List[Dict] = []
        self.conversation_history_b: List[Dict] = []
        
        # 存储工作线程
        self.api_worker = None
        
        # 存储当前气泡
        self.current_bubble = None
        
        # 存储消息列表
        self.messages: List[Message] = []
        
        # 存储相关变量
        self.current_save_path = ""
        
        # 超时定时器
        self.response_timeout_timer = QTimer()
        self.response_timeout_timer.timeout.connect(self.on_response_timeout)
        self.response_timeout_seconds = 40
        
        self.init_ui()
    
    def load_api_key(self):
        """从配置文件加载API密钥（支持加密和明文格式）"""
        config_file = "comet_config.json"
        
        if os.path.exists(config_file):
            try:
                with open(config_file, 'r', encoding='utf-8') as f:
                    config = json.load(f)
                    
                    # 首先尝试加载加密的API密钥
                    if 'api_key_encrypted' in config:
                        encrypted_key = config.get('api_key_encrypted', '')
                        if encrypted_key:
                            # 解密API密钥
                            decrypted_key = self.aes_helper.decrypt(encrypted_key)
                            if decrypted_key:
                                return decrypted_key
                    
                    # 如果没有加密的密钥，尝试加载明文的（兼容旧版本）
                    elif 'api_key' in config:
                        plain_key = config.get('api_key', '').strip()
                        if plain_key:
                            # 将明文密钥加密保存
                            self.save_api_key(plain_key)
                            return plain_key
                    
            except Exception as e:
                print(f"读取配置文件失败: {e}")
        
        return ""
    
    def save_api_key(self, api_key):
        """加密并保存API密钥到配置文件"""
        config_file = "comet_config.json"
        
        try:
            # 加密API密钥
            encrypted_key = self.aes_helper.encrypt(api_key)
            
            # 创建配置
            config = {
                'api_key_encrypted': encrypted_key,
                'last_updated': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }
            
            # 如果配置文件已存在，读取现有配置
            if os.path.exists(config_file):
                with open(config_file, 'r', encoding='utf-8') as f:
                    existing_config = json.load(f)
                    # 移除可能存在的明文API密钥
                    if 'api_key' in existing_config:
                        del existing_config['api_key']
                    # 更新配置
                    existing_config.update(config)
                    config = existing_config
            
            with open(config_file, 'w', encoding='utf-8') as f:
                json.dump(config, f, indent=2, ensure_ascii=False)
            
            return True
        except Exception as e:
            print(f"保存配置文件失败: {e}")
            return False
    
    def test_api_key(self, api_key):
        """测试API密钥是否有效"""
        if not api_key:
            return False
        
        try:
            headers = {
                "Content-Type": "application/json",
                "Authorization": f"Bearer {api_key}"
            }
            
            data = {
                "model": "glm-4-flash",
                "messages": [{"role": "user", "content": "测试连接，请回复'连接成功'"}],
                "stream": False
            }
            
            response = requests.post(
                "https://open.bigmodel.cn/api/paas/v4/chat/completions",
                headers=headers,
                json=data,
                timeout=5
            )
            
            return response.status_code == 200
        except:
            return False
    
    def show_api_key_dialog(self):
        """显示API密钥设置对话框"""
        while True:
            dialog = ApiKeyDialog(self, self.api_key)
            result = dialog.exec_()
            
            if result == 0:  # 用户点击"完成"
                new_api_key = dialog.get_api_key()
                
                if not new_api_key:
                    QMessageBox.warning(self, "输入为空", "请输入API密钥")
                    continue
                
                # 测试新的API密钥
                if self.test_api_key(new_api_key):
                    # 保存API密钥
                    if self.save_api_key(new_api_key):
                        self.api_key = new_api_key
                        QMessageBox.information(self, "成功", "API密钥设置成功！")
                        break
                    else:
                        QMessageBox.warning(self, "保存失败", "保存API密钥失败，请检查配置文件权限")
                else:
                    QMessageBox.warning(self, "连接失败", "API密钥无效，请重新输入")
            else:  # 用户点击"稍后设置"
                if not self.api_key:
                    QMessageBox.warning(self, "注意", "没有有效的API密钥，对话功能将无法使用。\n您可以在菜单栏的'设置'中随时设置API密钥。")
                break
    
    def set_api_key(self):
        """设置API密钥（菜单调用）"""
        self.show_api_key_dialog()
        
    def init_ui(self):
        """初始化UI"""
        self.setWindowTitle("ChatBots")
        self.setGeometry(100, 100, 1000, 700)
        
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        
        # 控制面板
        control_panel = QHBoxLayout()
        
        theme_label = QLabel("对话主题:")
        self.theme_input = QLineEdit()
        self.theme_input.setPlaceholderText("请输入对话主题")
        self.theme_input.setMinimumWidth(300)
        self.theme_input.setText("今天发生了什么有趣的事情？说来听听呗")
        
        self.start_btn = QPushButton("开始对话")
        self.start_btn.clicked.connect(self.start_conversation)
        
        self.pause_btn = QPushButton("暂停")
        self.pause_btn.clicked.connect(self.toggle_pause)
        self.pause_btn.setEnabled(False)
        
        self.clear_btn = QPushButton("清除对话")
        self.clear_btn.clicked.connect(self.clear_conversation)
        
        self.save_btn = QPushButton("保存对话")
        self.save_btn.clicked.connect(self.save_conversation)
        self.save_btn.setEnabled(False)
        
        self.load_btn = QPushButton("加载对话")
        self.load_btn.clicked.connect(self.load_conversation)
        
        # 修改：将重新连接按钮改为API密钥设置按钮
        self.api_key_btn = QPushButton("API密钥设置")
        self.api_key_btn.clicked.connect(self.set_api_key)
        
        control_panel.addWidget(theme_label)
        control_panel.addWidget(self.theme_input)
        control_panel.addWidget(self.start_btn)
        control_panel.addWidget(self.pause_btn)
        control_panel.addWidget(self.clear_btn)
        control_panel.addWidget(self.save_btn)
        control_panel.addWidget(self.load_btn)
        control_panel.addWidget(self.api_key_btn)
        control_panel.addStretch()
        
        main_layout.addLayout(control_panel)
        
        # 状态信息栏
        status_info_panel = QHBoxLayout()
        self.status_info = QLabel("就绪")
        status_info_panel.addWidget(self.status_info)
        status_info_panel.addStretch()
        main_layout.addLayout(status_info_panel)
        
        # 对话显示区域
        chat_frame = QFrame()
        chat_frame.setFrameStyle(QFrame.StyledPanel | QFrame.Sunken)
        chat_layout = QVBoxLayout(chat_frame)
        chat_layout.setContentsMargins(0, 0, 0, 0)
        
        # 滚动区域
        self.scroll_area = QScrollArea()
        self.scroll_area.setWidgetResizable(True)
        self.scroll_area.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        
        # 优化滚动条
        scrollbar = self.scroll_area.verticalScrollBar()
        scrollbar.setStyleSheet("""
            QScrollBar:vertical {
                background: #f1f1f1;
                width: 12px;
            }
            QScrollBar::handle:vertical {
                background: #c1c1c1;
                border-radius: 6px;
            }
            QScrollBar::handle:vertical:hover {
                background: #a8a8a8;
            }
        """)
        
        # 滚动内容部件
        self.scroll_content = QWidget()
        self.scroll_layout = QVBoxLayout(self.scroll_content)
        self.scroll_layout.setAlignment(Qt.AlignTop)
        self.scroll_layout.addStretch()
        
        # 设置滚动内容部件的布局属性
        self.scroll_content.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Maximum)
        
        self.scroll_area.setWidget(self.scroll_content)
        chat_layout.addWidget(self.scroll_area)
        
        main_layout.addWidget(chat_frame)
        
        self.status_label = QLabel("就绪")
        main_layout.addWidget(self.status_label)
        
    def start_conversation(self):
        """开始对话"""
        # 检查API密钥
        if not self.api_key:
            QMessageBox.warning(self, "无API密钥", "请先设置API密钥")
            self.set_api_key()
            return
            
        self.theme = self.theme_input.text().strip()
        if not self.theme:
            self.status_label.setText("请输入对话主题")
            QMessageBox.warning(self, "警告", "请输入对话主题")
            return
            
        self.retry_count = 0
        
        # 重置状态
        self.conversation_active = True
        self.conversation_history_a.clear()
        self.conversation_history_b.clear()
        self.clear_conversation_display()
        
        # 更新按钮状态
        self.start_btn.setEnabled(False)
        self.pause_btn.setEnabled(True)
        self.theme_input.setEnabled(False)
        self.save_btn.setEnabled(True)
        
        # 为本次对话创建存储文件
        self.create_conversation_file()
        
        self.status_label.setText(f"对话开始，主题: {self.theme}")
        
        # 开始对话循环
        self.current_agent = AgentType.AGENT_A
        self.generate_next_response()
    
    def create_conversation_file(self):
        """创建对话存储文件"""
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        theme_clean = "".join(c for c in self.theme if c.isalnum() or c in (' ', '_', '-'))[:50]
        filename = f"对话记录_{timestamp}_{theme_clean}.json"
        
        # 创建存储目录
        if not os.path.exists("对话记录"):
            os.makedirs("对话记录")
        
        self.current_save_path = os.path.join("对话记录", filename)
        
        # 初始化文件内容
        file_data = {
            "theme": self.theme,
            "start_time": time.time(),
            "start_time_str": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "messages": []
        }
        
        with open(self.current_save_path, 'w', encoding='utf-8') as f:
            json.dump(file_data, f, ensure_ascii=False, indent=2)
    
    def save_message_to_file(self, message: Message):
        """保存消息到文件"""
        if not self.current_save_path or not os.path.exists(self.current_save_path):
            return
        
        try:
            # 读取现有数据
            with open(self.current_save_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            # 添加新消息
            message_dict = asdict(message)
            message_dict["timestamp_str"] = datetime.datetime.fromtimestamp(
                message.timestamp
            ).strftime("%Y-%m-%d %H:%M:%S")
            data["messages"].append(message_dict)
            data["last_update"] = time.time()
            data["last_update_str"] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            
            # 写回文件
            with open(self.current_save_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
                
        except Exception as e:
            self.status_label.setText(f"保存消息失败: {str(e)}")
    
    def save_conversation(self):
        """保存当前对话"""
        if not self.messages:
            QMessageBox.warning(self, "警告", "没有对话内容可保存")
            return
        
        # 如果已有保存文件，则直接更新
        if self.current_save_path and os.path.exists(self.current_save_path):
            # 重新保存所有消息
            try:
                with open(self.current_save_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                
                # 更新消息列表
                data["messages"] = []
                for msg in self.messages:
                    msg_dict = asdict(msg)
                    msg_dict["timestamp_str"] = datetime.datetime.fromtimestamp(
                        msg.timestamp
                    ).strftime("%Y-%m-%d %H:%M:%S")
                    data["messages"].append(msg_dict)
                
                data["last_update"] = time.time()
                data["last_update_str"] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                
                with open(self.current_save_path, 'w', encoding='utf-8') as f:
                    json.dump(data, f, ensure_ascii=False, indent=2)
                    
                self.status_label.setText(f"对话已保存到: {self.current_save_path}")
                QMessageBox.information(self, "成功", f"对话已保存到:\n{self.current_save_path}")
                
            except Exception as e:
                QMessageBox.warning(self, "错误", f"保存对话失败: {str(e)}")
        else:
            # 让用户选择保存位置
            file_path, _ = QFileDialog.getSaveFileName(
                self, "保存对话", "对话记录", "JSON文件 (*.json)"
            )
            if file_path:
                try:
                    data = {
                        "theme": self.theme,
                        "start_time": time.time(),
                        "start_time_str": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        "messages": []
                    }
                    
                    for msg in self.messages:
                        msg_dict = asdict(msg)
                        msg_dict["timestamp_str"] = datetime.datetime.fromtimestamp(
                            msg.timestamp
                        ).strftime("%Y-%m-%d %H:%M:%S")
                        data["messages"].append(msg_dict)
                    
                    with open(file_path, 'w', encoding='utf-8') as f:
                        json.dump(data, f, ensure_ascii=False, indent=2)
                    
                    self.current_save_path = file_path
                    self.status_label.setText(f"对话已保存到: {file_path}")
                    QMessageBox.information(self, "成功", f"对话已保存到:\n{file_path}")
                    
                except Exception as e:
                    QMessageBox.warning(self, "错误", f"保存对话失败: {str(e)}")
    
    def load_conversation(self):
        """加载对话记录"""
        file_path, _ = QFileDialog.getOpenFileName(
            self, "加载对话", "对话记录", "JSON文件 (*.json)"
        )
        
        if not file_path:
            return
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            # 清空当前对话
            self.clear_conversation()
            
            # 设置主题
            self.theme = data.get("theme", "未知主题")
            self.theme_input.setText(self.theme)
            
            # 加载消息
            self.messages.clear()
            loaded_messages = data.get("messages", [])
            
            for msg_data in loaded_messages:
                message = Message(
                    agent=msg_data.get("agent", ""),
                    content=msg_data.get("content", ""),
                    timestamp=msg_data.get("timestamp", time.time())
                )
                self.messages.append(message)
            
            # 重新构建对话历史
            self.conversation_history_a.clear()
            self.conversation_history_b.clear()
            
            for msg in self.messages:
                if msg.agent == "Agent_A":
                    self.conversation_history_a.append({"role": "assistant", "content": msg.content})
                    self.conversation_history_b.append({"role": "user", "content": msg.content})
                else:
                    self.conversation_history_b.append({"role": "assistant", "content": msg.content})
                    self.conversation_history_a.append({"role": "user", "content": msg.content})
            
            # 重新显示对话
            self.clear_conversation_display()
            for msg in self.messages:
                is_right = (msg.agent == "Agent_A")
                agent_name = "代理A" if msg.agent == "Agent_A" else "代理B"
                bubble = ChatBubble(agent_name, is_right)
                bubble.set_complete_content(msg.content)
                self.scroll_layout.insertWidget(self.scroll_layout.count() - 1, bubble)
            
            QTimer.singleShot(100, self.scroll_to_bottom)
            
            self.current_save_path = file_path
            self.save_btn.setEnabled(True)
            
            self.status_label.setText(f"已加载对话: {os.path.basename(file_path)}")
            QMessageBox.information(self, "成功", f"已加载对话记录，共{len(self.messages)}条消息")
            
        except Exception as e:
            QMessageBox.warning(self, "错误", f"加载对话失败: {str(e)}")
    
    def generate_next_response(self):
        """生成下一个代理的回复"""
        if not self.conversation_active:
            return
            
        self.response_timeout_timer.start(self.response_timeout_seconds * 1000)
        
        # 获取当前代理的系统提示 - 使用优化后的提示词
        if self.current_agent == AgentType.AGENT_A:
            system_prompt = f"""角色设定
你正在与另一位朋友进行轻松、有趣的闲聊。你们会围绕以下话题展开交流：
初始话题：{self.theme}

核心对话原则
1. 自然与生动：表现得像一个真实、健谈的人。多使用我觉得、哎呀我跟你说、记得有一次等口语化、带主观色彩的表达。
2. 简洁与犀利：回复应以精炼的短句为主，追求一针见血的效果，避免冗长和官方的描述。
3. 想象与延伸：不要局限在初始话题的字面意思。你可以（且鼓励你）从以下几个方向自然地转移话题，分享相关的、虚构但合理的小故事或感受：
    - 时间：聊聊刚才发生了什么，或者待会儿/以前打算/发生过什么相关的事？
    - 地点：这件事让你想起了在什么地方的类似经历？那里的环境、气氛如何？
    - 人物：你的朋友、同学、家人甚至路人有没有发生过什么相关的趣事？
    - 感受：在聊这件事的此时此刻，你是什么心情？为什么会联想到这些？
    （注意：不需要每次都说全这四个方面！想到哪个说哪个，关键是让对话自然流动起来，避免机械的问答。）
4. 自然衔接：你的回复可以自然地延伸话题，让对方能够接话，无需刻意提问或使用问句。

示例（如果主题是拖延症）：
- 不好的回复（局限于主题）：拖延症不好，要改。（太干瘪）
- 好的回复（运用了延伸）：哎呀别提了！我昨天赶报告拖到凌晨三点，困得灵魂出窍。突然想起我大学室友更绝，在网吧打游戏到截止前1小时才开始写论文，最后居然还拿了良！你说气不气人？
  （这个回复：包含了感受（困得灵魂出窍）、延伸了人物（大学室友）和时间（昨天/大学），并且自然地延伸了话题）

请使用纯文本格式，不要使用任何markdown格式（如星号、井号、加粗等）。

现在，让我们从 {self.theme} 开始，聊点有意思的吧！记住，我们是朋友在聊天，不是答题。"""
            
            history = self.conversation_history_a
        else:
            system_prompt = f"""角色设定
你正在与另一位朋友进行轻松、有趣的闲聊。你们会围绕以下话题展开交流：
初始话题：{self.theme}

核心对话原则
1. 自然与生动：表现得像一个真实、健谈的人。多使用我觉得、哎呀我跟你说、记得有一次等口语化、带主观色彩的表达。
2. 简洁与犀利：回复应以精炼的短句为主，追求一针见血的效果，避免冗长和官方的描述。
3. 想象与延伸：不要局限在初始话题的字面意思。你可以（且鼓励你）从以下几个方向自然地转移话题，分享相关的、虚构但合理的小故事或感受：
    - 时间：聊聊刚才发生了什么，或者待会儿/以前打算/发生过什么相关的事？
    - 地点：这件事让你想起了在什么地方的类似经历？那里的环境、气氛如何？
    - 人物：你的朋友、同学、家人甚至路人有没有发生过什么相关的趣事？
    - 感受：在聊这件事的此时此刻，你是什么心情？为什么会联想到这些？
    （注意：不需要每次都说全这四个方面！想到哪个说哪个，关键是让对话自然流动起来，避免机械的问答。）
4. 自然衔接：你的回复可以自然地延伸话题，让对方能够接话，无需刻意提问或使用问句。

示例（如果主题是拖延症）：
- 不好的回复（局限于主题）：拖延症不好，要改。（太干瘪）
- 好的回复（运用了延伸）：哎呀别提了！我昨天赶报告拖到凌晨三点，困得灵魂出窍。突然想起我大学室友更绝，在网吧打游戏到截止前1小时才开始写论文，最后居然还拿了良！你说气不气人？
  （这个回复：包含了感受（困得灵魂出窍）、延伸了人物（大学室友）和时间（昨天/大学），并且自然地延伸了话题）

请使用纯文本格式，不要使用任何markdown格式（如星号、井号、加粗等）。

现在，让我们从 {self.theme} 开始，聊点有意思的吧！记住，我们是朋友在聊天，不是答题。"""
            
            history = self.conversation_history_b
        
        # 构建完整的messages列表
        messages = [{"role": "system", "content": system_prompt}]
        
        # 添加对话历史
        for msg in history[-10:]:
            messages.append(msg)
        
        # 检查是否至少有一个user或assistant消息
        has_user_or_assistant = any(msg.get("role") in ["user", "assistant"] for msg in messages)
        if not has_user_or_assistant:
            initial_prompts = [
                f"嘿，聊聊{self.theme}吧！",
                f"关于{self.theme}，你怎么看？",
                f"{self.theme}，有意思！",
                f"说说{self.theme}吧！"
            ]
            initial_message = {"role": "user", "content": random.choice(initial_prompts)}
            messages.append(initial_message)
        
        # 创建聊天气泡
        is_right = (self.current_agent == AgentType.AGENT_A)
        agent_name = "代理A" if self.current_agent == AgentType.AGENT_A else "代理B"
        
        self.current_bubble = ChatBubble(agent_name, is_right)
        self.scroll_layout.insertWidget(self.scroll_layout.count() - 1, self.current_bubble)
        
        QTimer.singleShot(100, self.scroll_to_bottom)
        
        # 创建API工作线程
        self.api_worker = APIWorker(
            self.api_key,
            self.api_url,
            self.current_agent,
            messages,
            system_prompt
        )
        
        # 只连接必要的信号
        self.api_worker.response_complete.connect(self.on_response_complete)
        self.api_worker.error_occurred.connect(self.on_api_error)
        self.api_worker.timeout_occurred.connect(self.on_api_timeout)
        self.api_worker.finished.connect(self.on_api_finished)
        
        self.api_worker.start()
        
        self.status_label.setText(f"{agent_name} 正在思考...")
    
    def scroll_to_bottom(self):
        """滚动到底部"""
        scrollbar = self.scroll_area.verticalScrollBar()
        scrollbar.setValue(scrollbar.maximum())
        # 确保内容部件更新
        self.scroll_content.adjustSize()
    
    def on_response_complete(self, agent_type: str, full_response: str):
        """API响应完成"""
        self.response_timeout_timer.stop()
        
        if not self.conversation_active or not full_response.strip():
            return
        
        if len(full_response.strip()) < 2:
            self.status_label.setText(f"收到空响应，重试中... ({self.retry_count+1}/{self.max_retries})")
            self.retry_or_stop("收到空响应")
            return
            
        if self.current_bubble:
            self.current_bubble.set_complete_content(full_response)
        
        # 将AI回复保存到当前代理的历史
        ai_message = {"role": "assistant", "content": full_response}
        
        if agent_type == "Agent_A":
            self.conversation_history_a.append(ai_message)
        else:
            self.conversation_history_b.append(ai_message)
        
        # 为对方代理添加一个user消息
        user_message = {"role": "user", "content": full_response}
        if agent_type == "Agent_A":
            self.conversation_history_b.append(user_message)
        else:
            self.conversation_history_a.append(user_message)
        
        # 保存到消息列表
        message = Message(agent_type, full_response)
        self.messages.append(message)
        
        # 保存到文件
        self.save_message_to_file(message)
        
        # 重置重试计数器
        self.retry_count = 0
        
        # 切换到下一个代理
        self.switch_to_next_agent()
    
    def switch_to_next_agent(self):
        """切换到下一个代理"""
        # 切换代理
        self.current_agent = AgentType.AGENT_B if self.current_agent == AgentType.AGENT_A else AgentType.AGENT_A
        
        # 更新状态显示
        agent_name = "代理A" if self.current_agent == AgentType.AGENT_A else "代理B"
        self.status_label.setText(f"{agent_name} 准备发言...")
        
        # 短暂延迟后生成下一个回复
        QTimer.singleShot(500, self.generate_next_response)
    
    def on_api_error(self, error_msg: str):
        """API错误处理"""
        self.response_timeout_timer.stop()
        self.status_label.setText(f"API错误: {error_msg}")
        self.retry_or_stop(error_msg)
    
    def on_api_timeout(self):
        """API超时处理"""
        self.status_label.setText(f"API响应超时")
        self.retry_or_stop("API响应超时")
    
    def on_response_timeout(self):
        """响应超时处理"""
        self.status_label.setText("响应超时，正在重试...")
        if self.api_worker and self.api_worker.isRunning():
            self.api_worker.stop()
        self.retry_or_stop("响应超时")
    
    def retry_or_stop(self, error_msg: str):
        """重试或停止对话"""
        if self.retry_count < self.max_retries:
            self.retry_count += 1
            self.status_label.setText(f"错误: {error_msg}，重试中... ({self.retry_count}/{self.max_retries})")
            QTimer.singleShot(2000, self.generate_next_response)
        else:
            self.status_label.setText(f"错误: {error_msg}，已达到最大重试次数")
            QMessageBox.warning(self, "错误", f"发生错误: {error_msg}\n已达到最大重试次数，对话已停止")
            self.stop_conversation()
    
    def on_api_finished(self):
        """API线程完成"""
        self.api_worker = None
    
    def toggle_pause(self):
        """切换暂停/继续状态"""
        if self.conversation_active:
            # 暂停对话
            self.conversation_active = False
            self.response_timeout_timer.stop()
            self.pause_btn.setText("继续")
            self.status_label.setText("对话已暂停")
            
            # 停止API调用
            if self.api_worker and self.api_worker.isRunning():
                self.api_worker.stop()
        else:
            # 继续对话
            self.conversation_active = True
            self.pause_btn.setText("暂停")
            self.status_label.setText("对话继续")
            
            # 继续生成
            self.generate_next_response()
    
    def clear_conversation(self):
        """清除对话"""
        self.stop_conversation()
        self.clear_conversation_display()
        
        self.conversation_history_a.clear()
        self.conversation_history_b.clear()
        self.messages.clear()
        self.current_bubble = None
        self.retry_count = 0
        
        self.status_label.setText("对话已清除")
        self.save_btn.setEnabled(False)
        self.current_save_path = ""
    
    def clear_conversation_display(self):
        """清除对话显示"""
        for i in reversed(range(self.scroll_layout.count() - 1)):
            item = self.scroll_layout.itemAt(i)
            if item.widget():
                item.widget().deleteLater()
    
    def stop_conversation(self):
        """停止对话"""
        self.conversation_active = False
        self.response_timeout_timer.stop()
        
        # 停止API线程
        if self.api_worker and self.api_worker.isRunning():
            self.api_worker.stop()
            self.api_worker.wait(2000)
        
        # 重置按钮状态
        self.start_btn.setEnabled(True)
        self.pause_btn.setText("暂停")
        self.pause_btn.setEnabled(False)
        self.theme_input.setEnabled(True)
        
        self.status_label.setText("对话已停止")
    
    def closeEvent(self, event):
        """窗口关闭事件"""
        self.stop_conversation()
        super().closeEvent(event)

# ==================== 主程序 ====================

def main():
    app = QApplication(sys.argv)
    app.setStyle('Fusion')
    
    # 设置应用图标
    if os.path.exists("icon.ico"):
        app.setWindowIcon(QIcon("icon.ico"))
    
    app.setStyleSheet("""
        QMainWindow {
            background-color: #f5f5f5;
        }
        QPushButton {
            background-color: #4CAF50;
            color: white;
            border: none;
            padding: 8px 16px;
            border-radius: 4px;
            font-weight: bold;
        }
        QPushButton:hover {
            background-color: #45a049;
        }
        QPushButton:disabled {
            background-color: #cccccc;
        }
        QPushButton#pause_btn {
            background-color: #ff9800;
        }
        QPushButton#pause_btn:hover {
            background-color: #e68900;
        }
        QPushButton#clear_btn {
            background-color: #f44336;
        }
        QPushButton#clear_btn:hover {
            background-color: #d32f2f;
        }
        QPushButton#save_btn {
            background-color: #9C27B0;
        }
        QPushButton#save_btn:hover {
            background-color: #7B1FA2;
        }
        QPushButton#load_btn {
            background-color: #2196F3;
        }
        QPushButton#load_btn:hover {
            background-color: #0b7dda;
        }
        QPushButton#api_key_btn {
            background-color: #607D8B;
        }
        QPushButton#api_key_btn:hover {
            background-color: #455A64;
        }
        QLineEdit {
            padding: 8px;
            border: 1px solid #cccccc;
            border-radius: 4px;
        }
        QLabel {
            padding: 5px;
        }
        QScrollArea {
            border: none;
            background-color: white;
        }
    """)
    
    window = MainWindow()
    window.show()
    
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()