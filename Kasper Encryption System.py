"""
Kasper Encryption System
-------------------------
A custom block-cipher encryption suite combining a Diffie-Hellman key
exchange with an AES-derived substitution-permutation cipher, RSA-based
digital signatures, and built-in cryptanalysis tooling (avalanche effect
testing and performance benchmarking against standard AES).

Developed by Hamdan.
"""

import tkinter as tk
from tkinter import ttk, filedialog, scrolledtext, messagebox
import os
import random
import base64
import hashlib
import platform
import subprocess
import time
import statistics

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding


# ---------------------------------------------------------------------------
# GF(2^8) arithmetic for a genuine MDS (Maximum Distance Separable) mixing
# layer, using the same field and MixColumns/InvMixColumns matrices as AES.
# This is what actually gives the cipher diffusion: shift_rows only moves
# bytes around, so without a real Galois-field mix, a change in one byte can
# never influence more than one byte of the next round's output.
# ---------------------------------------------------------------------------
def _gf_multiply(a, b):
    """Multiply two bytes in GF(2^8) with the AES reduction polynomial x^8+x^4+x^3+x+1 (0x11B)."""
    result = 0
    for _ in range(8):
        if b & 1:
            result ^= a
        carry = a & 0x80
        a = (a << 1) & 0xFF
        if carry:
            a ^= 0x1B
        b >>= 1
    return result & 0xFF


_MIX_MATRIX = (
    (2, 3, 1, 1),
    (1, 2, 3, 1),
    (1, 1, 2, 3),
    (3, 1, 1, 2),
)
_INV_MIX_MATRIX = (
    (14, 11, 13, 9),
    (9, 14, 11, 13),
    (13, 9, 14, 11),
    (11, 13, 9, 14),
)


# ---------------------------------------------------------------------------
# Core cipher: Kasper Encryption
# ---------------------------------------------------------------------------
class KasperEncryption:
    """
    Implements the Kasper cipher: a 128-bit block cipher built from custom
    S-boxes, a byte-rotation permutation layer, a Galois-field (GF(2^8))
    MDS mixing layer, and round-key mixing, wrapped in CBC mode. Key
    material is negotiated with Diffie-Hellman and stretched with
    PBKDF2-HMAC-SHA256.
    """

    def __init__(self):
        self.generate_custom_sboxes()
        self.block_size = 16
        self.prime = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74
        self.generator = 2

    def generate_custom_sboxes(self):
        self.sbox = list(range(256))
        random.seed(42)
        random.shuffle(self.sbox)
        self.inv_sbox = [0] * 256
        for i in range(256):
            self.inv_sbox[self.sbox[i]] = i

    def generate_key_pair(self):
        private_key = random.randint(1, self.prime - 1)
        public_key = pow(self.generator, private_key, self.prime)
        return private_key, public_key

    def generate_shared_secret(self, private_key, other_public_key):
        return pow(other_public_key, private_key, self.prime)

    def derive_encryption_key(self, shared_secret, salt=None):
        if salt is None:
            salt = os.urandom(16)
        secret_bytes = shared_secret.to_bytes((shared_secret.bit_length() + 7) // 8, byteorder='big')
        key = hashlib.pbkdf2_hmac('sha256', secret_bytes, salt, 100000, 32)
        return key, salt

    def pad(self, data):
        padding_length = self.block_size - (len(data) % self.block_size)
        return data + bytes([padding_length]) * padding_length

    def unpad(self, data):
        return data[:-data[-1]]

    def substitute_bytes(self, block, inverse=False):
        sbox_to_use = self.inv_sbox if inverse else self.sbox
        return bytes(sbox_to_use[b] for b in block)

    def shift_rows(self, block, inverse=False):
        matrix = [list(block[i:i+4]) for i in range(0, 16, 4)]
        matrix = list(map(list, zip(*matrix)))
        for i in range(1, 4):
            shift = i if not inverse else 4 - i
            matrix[i] = matrix[i][shift:] + matrix[i][:shift]
        matrix = list(map(list, zip(*matrix)))
        return bytes(b for row in matrix for b in row)

    def mix_columns(self, block, inverse=False):
        """Applies an AES-standard MDS matrix over GF(2^8) to each 4-byte
        group of the state, so every output byte depends on all four input
        bytes in its group. Grouping here deliberately mirrors the groups
        that shift_rows draws its bytes *from* (each shifted group pulls one
        byte from each original group) rather than the group shift_rows
        leaves fixed — that pairing is what gives full 16-byte diffusion
        after two rounds, matching the avalanche effect test results in the
        Cryptanalysis tab."""
        mix_matrix = _INV_MIX_MATRIX if inverse else _MIX_MATRIX
        output = bytearray(16)
        for g in range(0, 16, 4):
            group = block[g:g+4]
            for row_idx, coeffs in enumerate(mix_matrix):
                value = 0
                for coeff, byte in zip(coeffs, group):
                    value ^= _gf_multiply(coeff, byte)
                output[g + row_idx] = value
        return bytes(output)

    def add_round_key(self, block, round_key):
        return bytes(a ^ b for a, b in zip(block, round_key))

    def encrypt_block(self, block, key):
        round_keys = [hashlib.sha256(key + bytes([i])).digest()[:16] for i in range(11)]
        state = self.add_round_key(block, round_keys[0])
        for i in range(1, 10):
            state = self.substitute_bytes(state)
            state = self.shift_rows(state)
            state = self.mix_columns(state)
            state = self.add_round_key(state, round_keys[i])
        state = self.substitute_bytes(state)
        state = self.shift_rows(state)
        state = self.add_round_key(state, round_keys[10])
        return state

    def decrypt_block(self, block, key):
        round_keys = [hashlib.sha256(key + bytes([i])).digest()[:16] for i in range(11)]
        state = self.add_round_key(block, round_keys[10])
        state = self.shift_rows(state, inverse=True)
        state = self.substitute_bytes(state, inverse=True)
        for i in range(9, 0, -1):
            state = self.add_round_key(state, round_keys[i])
            state = self.mix_columns(state, inverse=True)
            state = self.shift_rows(state, inverse=True)
            state = self.substitute_bytes(state, inverse=True)
        state = self.add_round_key(state, round_keys[0])
        return state

    def encrypt(self, data, key):
        iv = os.urandom(16)
        padded_data = self.pad(data)
        encrypted_blocks = []
        prev_block = iv
        for i in range(0, len(padded_data), self.block_size):
            block = padded_data[i:i+self.block_size]
            mixed = bytes(a ^ b for a, b in zip(block, prev_block))
            encrypted = self.encrypt_block(mixed, key)
            encrypted_blocks.append(encrypted)
            prev_block = encrypted
        return iv + b''.join(encrypted_blocks)

    def decrypt(self, encrypted_data, key):
        iv = encrypted_data[:16]
        ciphertext = encrypted_data[16:]
        decrypted_blocks = []
        prev_block = iv
        for i in range(0, len(ciphertext), self.block_size):
            block = ciphertext[i:i+self.block_size]
            decrypted = self.decrypt_block(block, key)
            original = bytes(a ^ b for a, b in zip(decrypted, prev_block))
            decrypted_blocks.append(original)
            prev_block = block
        return self.unpad(b''.join(decrypted_blocks))


# ---------------------------------------------------------------------------
# Digital signatures (RSA)
# ---------------------------------------------------------------------------
class DigitalSignatureManager:
    """Manages all digital signature operations using RSA."""

    def generate_keys(self):
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        return private_key, private_key.public_key()

    def save_key_to_pem(self, key, filename):
        if isinstance(key, rsa.RSAPrivateKey):
            pem = key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
        else:
            pem = key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        with open(filename, 'wb') as f:
            f.write(pem)

    def load_private_key(self, filename):
        with open(filename, "rb") as key_file:
            return serialization.load_pem_private_key(key_file.read(), password=None)

    def load_public_key(self, filename):
        with open(filename, "rb") as key_file:
            return serialization.load_pem_public_key(key_file.read())

    def sign_file(self, private_key, file_path):
        with open(file_path, 'rb') as f:
            data_to_sign = f.read()
        return private_key.sign(
            data_to_sign,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )

    def verify_signature(self, public_key, file_path, signature):
        with open(file_path, 'rb') as f:
            data_to_verify = f.read()
        try:
            public_key.verify(
                signature,
                data_to_verify,
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256()
            )
            return True
        except InvalidSignature:
            return False


# ---------------------------------------------------------------------------
# Cryptanalysis tooling: avalanche effect + performance benchmarking vs AES
# ---------------------------------------------------------------------------
class CryptanalysisSuite:
    """
    Research-oriented evaluation tools for the Kasper cipher:

    1. Avalanche effect testing — measures how much of the ciphertext
       changes (in bits) when a single input bit is flipped. A well-mixed
       block cipher should sit close to 50% for both plaintext and key
       perturbations.

    2. Performance benchmarking — times Kasper's own encrypt/decrypt path
       against the industry-standard AES-256-CBC implementation from the
       `cryptography` library, across several payload sizes, and reports
       throughput in MB/s along with a relative speed ratio.
    """

    @staticmethod
    def _hamming_distance_bits(a, b):
        return sum(bin(x ^ y).count("1") for x, y in zip(a, b))

    def run_avalanche_test(self, cipher, key, trials=128, block_size=16):
        """Flip a single random bit of a random plaintext block and measure
        the fraction of output bits that change, repeated over many trials."""
        plaintext_results = []
        key_results = []

        for _ in range(trials):
            block = os.urandom(block_size)
            baseline = cipher.encrypt_block(block, key)

            # --- Plaintext avalanche ---
            bit_index = random.randint(0, block_size * 8 - 1)
            byte_index, bit_offset = divmod(bit_index, 8)
            flipped = bytearray(block)
            flipped[byte_index] ^= (1 << bit_offset)
            flipped_cipher = cipher.encrypt_block(bytes(flipped), key)
            diff_bits = self._hamming_distance_bits(baseline, flipped_cipher)
            plaintext_results.append(diff_bits / (block_size * 8) * 100)

            # --- Key avalanche ---
            key_bit_index = random.randint(0, len(key) * 8 - 1)
            kb_index, kb_offset = divmod(key_bit_index, 8)
            flipped_key = bytearray(key)
            flipped_key[kb_index] ^= (1 << kb_offset)
            flipped_key_cipher = cipher.encrypt_block(block, bytes(flipped_key))
            key_diff_bits = self._hamming_distance_bits(baseline, flipped_key_cipher)
            key_results.append(key_diff_bits / (block_size * 8) * 100)

        return {
            "trials": trials,
            "plaintext_avalanche": {
                "mean": statistics.mean(plaintext_results),
                "stdev": statistics.stdev(plaintext_results) if trials > 1 else 0.0,
                "min": min(plaintext_results),
                "max": max(plaintext_results),
            },
            "key_avalanche": {
                "mean": statistics.mean(key_results),
                "stdev": statistics.stdev(key_results) if trials > 1 else 0.0,
                "min": min(key_results),
                "max": max(key_results),
            },
        }

    def _aes_encrypt(self, data, key):
        iv = os.urandom(16)
        padder = sym_padding.PKCS7(128).padder()
        padded = padder.update(data) + padder.finalize()
        encryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
        return iv + encryptor.update(padded) + encryptor.finalize()

    def run_benchmark(self, cipher, kasper_key, sizes_kb=(4, 16, 64)):
        """Times Kasper vs AES-256-CBC across a set of payload sizes and
        returns throughput (MB/s) for each."""
        aes_key = os.urandom(32)
        results = []

        for size_kb in sizes_kb:
            data = os.urandom(size_kb * 1024)

            start = time.perf_counter()
            cipher.encrypt(data, kasper_key)
            kasper_elapsed = time.perf_counter() - start

            start = time.perf_counter()
            self._aes_encrypt(data, aes_key)
            aes_elapsed = time.perf_counter() - start

            mb = size_kb / 1024
            kasper_throughput = mb / kasper_elapsed if kasper_elapsed > 0 else float("inf")
            aes_throughput = mb / aes_elapsed if aes_elapsed > 0 else float("inf")

            results.append({
                "size_kb": size_kb,
                "kasper_ms": kasper_elapsed * 1000,
                "aes_ms": aes_elapsed * 1000,
                "kasper_mbps": kasper_throughput,
                "aes_mbps": aes_throughput,
                "ratio": (aes_throughput / kasper_throughput) if kasper_throughput > 0 else float("inf"),
            })

        return results


# ---------------------------------------------------------------------------
# Main application window
# ---------------------------------------------------------------------------
class KasperEncryptionGUI:

    PALETTE = {
        "bg": "#eef1f5",
        "panel": "#dde3ea",
        "navy": "#1f3a5f",
        "navy_dark": "#152845",
        "encrypt": "#2f6690",
        "decrypt": "#9a5b2e",
        "clear": "#3f6b4a",
        "text": "#22282f",
        "muted": "#5b6470",
        "accent": "#0e6e5c",
    }

    BASE_FONT = ("Helvetica", 11)
    BOLD_FONT = ("Helvetica", 11, "bold")
    HEADER_FONT = ("Helvetica", 19, "bold")
    SUBHEADER_FONT = ("Helvetica", 13, "bold")
    MONO_FONT = ("Consolas", 10)

    def __init__(self, root):
        self.root = root
        self.root.title("Kasper Encryption System")
        self.root.geometry("980x760")
        self.root.minsize(860, 640)
        self.root.configure(bg=self.PALETTE["bg"])

        p = self.PALETTE
        self.style = ttk.Style()
        try:
            self.style.theme_use("clam")
        except tk.TclError:
            pass
        self.style.configure("TFrame", background=p["bg"])
        self.style.configure("TLabelframe", background=p["panel"], foreground=p["text"])
        self.style.configure("TLabelframe.Label", background=p["panel"], foreground=p["navy_dark"], font=self.BOLD_FONT)
        self.style.configure("TNotebook", background=p["bg"])
        self.style.configure("TNotebook.Tab", font=self.BOLD_FONT, padding=(14, 8))
        self.style.configure("TEntry", fieldbackground="#ffffff", font=self.BASE_FONT)
        self.style.configure("TLabel", background=p["bg"], foreground=p["text"], font=self.BASE_FONT)
        self.style.configure("Header.TLabel", background=p["bg"], foreground=p["navy_dark"], font=self.HEADER_FONT)
        self.style.configure("Sub.TLabel", background=p["bg"], foreground=p["muted"], font=("Helvetica", 11, "italic"))
        self.style.configure("Panel.TLabel", background=p["panel"], foreground=p["text"], font=self.BASE_FONT)
        self.style.configure("PanelBold.TLabel", background=p["panel"], foreground=p["navy_dark"], font=self.SUBHEADER_FONT)

        self.style.configure("TButton", font=self.BOLD_FONT, padding=8)
        self.style.configure("Encrypt.TButton", font=self.BOLD_FONT, padding=8)
        self.style.configure("Decrypt.TButton", font=self.BOLD_FONT, padding=8)
        self.style.configure("Clear.TButton", font=self.BOLD_FONT, padding=8)
        self.style.map("Encrypt.TButton", background=[("!disabled", p["encrypt"])], foreground=[("!disabled", "#ffffff")])
        self.style.map("Decrypt.TButton", background=[("!disabled", p["decrypt"])], foreground=[("!disabled", "#ffffff")])
        self.style.map("Clear.TButton", background=[("!disabled", p["clear"])], foreground=[("!disabled", "#ffffff")])
        self.style.map("TButton", background=[("!disabled", p["navy"])], foreground=[("!disabled", "#ffffff")])

        self.style.configure("Treeview", font=self.BASE_FONT, rowheight=26, background="#ffffff", fieldbackground="#ffffff")
        self.style.configure("Treeview.Heading", font=self.BOLD_FONT, background=p["panel"], foreground=p["navy_dark"])

        self.kasper = KasperEncryption()
        self.signature_manager = DigitalSignatureManager()
        self.analysis = CryptanalysisSuite()
        self.generate_new_keys()
        self.setup_ui()

    # -- layout -------------------------------------------------------
    def setup_ui(self):
        self.main_frame = ttk.Frame(self.root, padding="14")
        self.main_frame.pack(fill=tk.BOTH, expand=True)

        self.header_frame = ttk.Frame(self.main_frame)
        self.header_frame.pack(fill=tk.X, pady=(0, 6))
        ttk.Label(self.header_frame, text="Kasper Encryption System", style="Header.TLabel").pack()
        ttk.Label(
            self.header_frame,
            text="Diffie-Hellman key exchange · custom AES-derived block cipher · RSA signatures",
            style="Sub.TLabel"
        ).pack(pady=(2, 0))

        self.tab_control = ttk.Notebook(self.main_frame)
        self.tab_control.pack(fill=tk.BOTH, expand=True, pady=10)
        self.text_tab = ttk.Frame(self.tab_control)
        self.file_tab = ttk.Frame(self.tab_control)
        self.key_tab = ttk.Frame(self.tab_control)
        self.signature_tab = ttk.Frame(self.tab_control)
        self.analysis_tab = ttk.Frame(self.tab_control)
        self.tab_control.add(self.text_tab, text="Text Encryption")
        self.tab_control.add(self.file_tab, text="File Encryption")
        self.tab_control.add(self.key_tab, text="Key Information")
        self.tab_control.add(self.signature_tab, text="Digital Signature")
        self.tab_control.add(self.analysis_tab, text="Cryptanalysis")
        self.setup_text_tab()
        self.setup_file_tab()
        self.setup_key_tab()
        self.setup_signature_tab()
        self.setup_analysis_tab()
        self.create_footer()

    def generate_new_keys(self):
        self.private_key, self.public_key = self.kasper.generate_key_pair()
        self.shared_secret = self.kasper.generate_shared_secret(self.private_key, self.public_key)
        self.encryption_key, self.salt = self.kasper.derive_encryption_key(self.shared_secret)
        if hasattr(self, 'key_info_frame'):
            self.update_key_info()

    def setup_text_tab(self):
        text_main_frame = ttk.Frame(self.text_tab)
        text_main_frame.pack(fill=tk.BOTH, expand=True)
        input_frame = ttk.LabelFrame(text_main_frame, text="Input Text")
        input_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        self.input_text = scrolledtext.ScrolledText(input_frame, height=10, font=self.BASE_FONT, wrap=tk.WORD)
        self.input_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        buttons_frame = ttk.Frame(text_main_frame)
        buttons_frame.pack(fill=tk.X, padx=10, pady=10)
        ttk.Button(buttons_frame, text="Encrypt Text", command=self.encrypt_text, style="Encrypt.TButton").pack(side=tk.LEFT, padx=5)
        ttk.Button(buttons_frame, text="Decrypt Text", command=self.decrypt_text, style="Decrypt.TButton").pack(side=tk.LEFT, padx=5)
        ttk.Button(buttons_frame, text="Clear", command=self.clear_text, style="Clear.TButton").pack(side=tk.RIGHT, padx=5)
        output_frame = ttk.LabelFrame(text_main_frame, text="Output Text")
        output_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        self.output_text = scrolledtext.ScrolledText(output_frame, height=10, font=self.BASE_FONT, wrap=tk.WORD)
        self.output_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        status_frame = ttk.LabelFrame(text_main_frame, text="Status")
        status_frame.pack(fill=tk.X, padx=10, pady=10)
        self.text_status_text = scrolledtext.ScrolledText(status_frame, height=4, font=self.BASE_FONT)
        self.text_status_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

    def setup_file_tab(self):
        file_frame = ttk.LabelFrame(self.file_tab, text="File Selection")
        file_frame.pack(fill=tk.X, padx=10, pady=10)
        self.file_path_var = tk.StringVar()
        ttk.Entry(file_frame, textvariable=self.file_path_var, width=60, font=self.BASE_FONT).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5, pady=10)
        ttk.Button(file_frame, text="Browse", command=self.browse_file).pack(side=tk.RIGHT, padx=5, pady=10)
        op_frame = ttk.Frame(self.file_tab)
        op_frame.pack(fill=tk.X, padx=10, pady=10)
        ttk.Button(op_frame, text="Encrypt File", command=self.encrypt_file, style="Encrypt.TButton").pack(side=tk.LEFT, padx=5)
        ttk.Button(op_frame, text="Decrypt File", command=self.decrypt_file, style="Decrypt.TButton").pack(side=tk.LEFT, padx=5)
        status_frame = ttk.LabelFrame(self.file_tab, text="Status")
        status_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        self.status_text = scrolledtext.ScrolledText(status_frame, height=15, font=self.BASE_FONT)
        self.status_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

    def setup_key_tab(self):
        self.key_info_frame = ttk.Frame(self.key_tab, padding=10)
        self.key_info_frame.pack(fill=tk.BOTH, expand=True)
        self.update_key_info()

    def setup_signature_tab(self):
        key_frame = ttk.LabelFrame(self.signature_tab, text="1. Key Management")
        key_frame.pack(fill=tk.X, padx=10, pady=10)
        ttk.Button(key_frame, text="Generate & Save New RSA Key Pair", command=self.handle_generate_rsa_keys).pack(pady=5, padx=5)
        sign_frame = ttk.LabelFrame(self.signature_tab, text="2. Create Signature")
        sign_frame.pack(fill=tk.X, padx=10, pady=5)
        ttk.Button(sign_frame, text="Load Private Key & Sign File", command=self.handle_sign_file).pack(pady=5, padx=5)
        ttk.Label(sign_frame, text="Generated Signature (Base64):").pack(anchor=tk.W, padx=5)
        self.signature_display_text = scrolledtext.ScrolledText(sign_frame, height=5, font=self.MONO_FONT)
        self.signature_display_text.pack(fill=tk.X, expand=True, padx=5, pady=5)
        verify_frame = ttk.LabelFrame(self.signature_tab, text="3. Verify Signature")
        verify_frame.pack(fill=tk.X, padx=10, pady=5)
        ttk.Button(verify_frame, text="Load Public Key & Verify File", command=self.handle_verify_file).pack(pady=5, padx=5)
        self.verify_status_label = ttk.Label(verify_frame, text="Verification Status: PENDING", font=("Helvetica", 13, "bold"))
        self.verify_status_label.pack(pady=10)

    # -- Cryptanalysis tab ---------------------------------------------
    def setup_analysis_tab(self):
        container = ttk.Frame(self.analysis_tab, padding=10)
        container.pack(fill=tk.BOTH, expand=True)

        intro = ttk.Label(
            container,
            text="Evaluate the Kasper cipher's diffusion strength and measure its throughput "
                 "against the AES-256-CBC reference implementation.",
            style="Sub.TLabel", wraplength=880, justify=tk.LEFT
        )
        intro.pack(fill=tk.X, pady=(0, 12))

        # --- Avalanche effect section ---
        avalanche_frame = ttk.LabelFrame(container, text="Avalanche Effect Test")
        avalanche_frame.pack(fill=tk.X, padx=2, pady=8)

        av_controls = ttk.Frame(avalanche_frame)
        av_controls.pack(fill=tk.X, padx=8, pady=8)
        ttk.Label(av_controls, text="Trials:", style="Panel.TLabel").pack(side=tk.LEFT, padx=(0, 6))
        self.avalanche_trials_var = tk.StringVar(value="128")
        ttk.Entry(av_controls, textvariable=self.avalanche_trials_var, width=8, font=self.BASE_FONT).pack(side=tk.LEFT, padx=(0, 12))
        ttk.Button(av_controls, text="Run Avalanche Test", command=self.handle_run_avalanche, style="Encrypt.TButton").pack(side=tk.LEFT)

        self.avalanche_summary_label = ttk.Label(
            avalanche_frame,
            text="No test run yet. A well-diffused block cipher should average close to 50% bit change "
                 "for both a single-bit plaintext flip and a single-bit key flip.",
            style="Panel.TLabel", wraplength=880, justify=tk.LEFT
        )
        self.avalanche_summary_label.pack(fill=tk.X, padx=8, pady=(0, 8))

        av_columns = ("metric", "plaintext", "key")
        self.avalanche_tree = ttk.Treeview(avalanche_frame, columns=av_columns, show="headings", height=4)
        self.avalanche_tree.heading("metric", text="Statistic")
        self.avalanche_tree.heading("plaintext", text="Plaintext-Bit Flip (% bits changed)")
        self.avalanche_tree.heading("key", text="Key-Bit Flip (% bits changed)")
        self.avalanche_tree.column("metric", width=160, anchor=tk.W)
        self.avalanche_tree.column("plaintext", width=280, anchor=tk.CENTER)
        self.avalanche_tree.column("key", width=280, anchor=tk.CENTER)
        self.avalanche_tree.pack(fill=tk.X, padx=8, pady=(0, 10))

        # --- Benchmark section ---
        bench_frame = ttk.LabelFrame(container, text="Performance Benchmark: Kasper vs. AES-256-CBC")
        bench_frame.pack(fill=tk.BOTH, expand=True, padx=2, pady=8)

        bench_controls = ttk.Frame(bench_frame)
        bench_controls.pack(fill=tk.X, padx=8, pady=8)
        ttk.Label(bench_controls, text="Payload sizes (KB, comma-separated):", style="Panel.TLabel").pack(side=tk.LEFT, padx=(0, 6))
        self.bench_sizes_var = tk.StringVar(value="4, 16, 64")
        ttk.Entry(bench_controls, textvariable=self.bench_sizes_var, width=18, font=self.BASE_FONT).pack(side=tk.LEFT, padx=(0, 12))
        ttk.Button(bench_controls, text="Run Benchmark", command=self.handle_run_benchmark, style="Decrypt.TButton").pack(side=tk.LEFT)

        bench_columns = ("size", "kasper_ms", "kasper_mbps", "aes_ms", "aes_mbps", "ratio")
        self.bench_tree = ttk.Treeview(bench_frame, columns=bench_columns, show="headings", height=6)
        self.bench_tree.heading("size", text="Payload")
        self.bench_tree.heading("kasper_ms", text="Kasper Time (ms)")
        self.bench_tree.heading("kasper_mbps", text="Kasper (MB/s)")
        self.bench_tree.heading("aes_ms", text="AES-256 Time (ms)")
        self.bench_tree.heading("aes_mbps", text="AES-256 (MB/s)")
        self.bench_tree.heading("ratio", text="AES Speed-up (x)")
        for col in bench_columns:
            self.bench_tree.column(col, width=150, anchor=tk.CENTER)
        self.bench_tree.pack(fill=tk.BOTH, expand=True, padx=8, pady=(0, 6))

        self.bench_note_label = ttk.Label(
            bench_frame,
            text="Note: Kasper is a pure-Python reference implementation; AES-256-CBC here uses OpenSSL "
                 "via the `cryptography` library's hardware-accelerated bindings, so this is a fair "
                 "real-world throughput comparison rather than an apples-to-apples language benchmark.",
            style="Panel.TLabel", wraplength=880, justify=tk.LEFT
        )
        self.bench_note_label.pack(fill=tk.X, padx=8, pady=(0, 8))

    def handle_run_avalanche(self):
        try:
            trials = max(2, int(self.avalanche_trials_var.get()))
        except ValueError:
            messagebox.showerror("Invalid Input", "Trials must be a whole number.")
            return
        try:
            results = self.analysis.run_avalanche_test(self.kasper, self.encryption_key, trials=trials)
        except Exception as e:
            messagebox.showerror("Error", f"Avalanche test failed: {e}")
            return

        for row in self.avalanche_tree.get_children():
            self.avalanche_tree.delete(row)

        pt = results["plaintext_avalanche"]
        ky = results["key_avalanche"]
        rows = [
            ("Mean", f"{pt['mean']:.2f}%", f"{ky['mean']:.2f}%"),
            ("Std. Deviation", f"{pt['stdev']:.2f}%", f"{ky['stdev']:.2f}%"),
            ("Minimum", f"{pt['min']:.2f}%", f"{ky['min']:.2f}%"),
            ("Maximum", f"{pt['max']:.2f}%", f"{ky['max']:.2f}%"),
        ]
        for row in rows:
            self.avalanche_tree.insert("", tk.END, values=row)

        verdict = "close to the 50% ideal" if 45 <= pt['mean'] <= 55 and 45 <= ky['mean'] <= 55 else "notably off the 50% ideal"
        self.avalanche_summary_label.config(
            text=f"Ran {results['trials']} trials. Average bit change from a single plaintext-bit flip: "
                 f"{pt['mean']:.2f}%. From a single key-bit flip: {ky['mean']:.2f}%. This is {verdict}, "
                 f"which indicates the cipher's diffusion is {'strong' if verdict.startswith('close') else 'weak'}."
        )

    def handle_run_benchmark(self):
        try:
            sizes = [int(s.strip()) for s in self.bench_sizes_var.get().split(",") if s.strip()]
            if not sizes:
                raise ValueError
        except ValueError:
            messagebox.showerror("Invalid Input", "Enter payload sizes as comma-separated whole numbers, e.g. 4, 16, 64")
            return

        for row in self.bench_tree.get_children():
            self.bench_tree.delete(row)

        try:
            results = self.analysis.run_benchmark(self.kasper, self.encryption_key, sizes_kb=sizes)
        except Exception as e:
            messagebox.showerror("Error", f"Benchmark failed: {e}")
            return

        for r in results:
            self.bench_tree.insert("", tk.END, values=(
                f"{r['size_kb']} KB",
                f"{r['kasper_ms']:.2f}",
                f"{r['kasper_mbps']:.2f}",
                f"{r['aes_ms']:.2f}",
                f"{r['aes_mbps']:.2f}",
                f"{r['ratio']:.1f}x",
            ))

    # -- update key info --------------------------------------------------
    def update_key_info(self):
        """Update the key information display with full details."""
        for widget in self.key_info_frame.winfo_children():
            widget.destroy()

        ttk.Label(self.key_info_frame, text="Encryption Key Details", font=self.SUBHEADER_FONT).grid(
            column=0, row=0, columnspan=2, sticky=tk.W, pady=10)

        details = {
            "Private Key:": str(self.private_key),
            "Public Key:": str(self.public_key),
            "Shared Secret:": str(self.shared_secret),
            "Salt (Base64):": base64.b64encode(self.salt).decode('utf-8'),
            "Derived Encryption Key (Hex):": self.encryption_key.hex()
        }

        row = 1
        for label, value in details.items():
            ttk.Label(self.key_info_frame, text=label).grid(column=0, row=row, sticky=tk.W, padx=5, pady=2)
            value_entry = scrolledtext.ScrolledText(self.key_info_frame, height=2, wrap=tk.WORD, font=self.MONO_FONT)
            value_entry.grid(column=1, row=row, sticky=tk.EW, padx=5, pady=2)
            value_entry.insert(tk.END, value)
            value_entry.config(state=tk.DISABLED)
            row += 1

        ttk.Label(self.key_info_frame, text="Algorithm Implementation", font=self.SUBHEADER_FONT).grid(
            column=0, row=row, columnspan=2, sticky=tk.W, pady=(20, 10))
        row += 1

        specs = {
            "Key Exchange:": "Diffie-Hellman",
            "Symmetric Encryption:": "Kasper cipher (custom AES-derived block cipher)",
            "Diffusion Layer:": "GF(2^8) MDS matrix mixing (AES-standard MixColumns)",
            "Block Size:": "128 bits (16 bytes)",
            "Mode of Operation:": "Cipher Block Chaining (CBC)",
            "Padding:": "PKCS#7",
            "Key Derivation:": "PBKDF2 with HMAC-SHA256",
            "PBKDF2 Iterations:": "100,000"
        }

        for label, value in specs.items():
            ttk.Label(self.key_info_frame, text=label).grid(column=0, row=row, sticky=tk.W, padx=5, pady=2)
            ttk.Label(self.key_info_frame, text=value, anchor="w").grid(column=1, row=row, sticky=tk.W, padx=5, pady=2)
            row += 1

        self.key_info_frame.columnconfigure(1, weight=1)
        ttk.Button(self.key_info_frame, text="Generate New Encryption Keys", command=self.generate_new_keys).grid(
            column=0, row=row, columnspan=2, pady=20)

    def browse_file(self):
        filename = filedialog.askopenfilename(title="Select a file")
        if filename:
            self.file_path_var.set(filename)

    def encrypt_text(self):
        plaintext = self.input_text.get("1.0", tk.END).strip().encode('utf-8')
        if not plaintext:
            self.show_status("Please enter text to encrypt.")
            return
        try:
            encrypted = self.kasper.encrypt(plaintext, self.encryption_key)
            self.output_text.delete("1.0", tk.END)
            self.output_text.insert("1.0", base64.b64encode(encrypted).decode('utf-8'))
            self.show_status("Text encrypted successfully!")
        except Exception as e:
            self.show_status(f"Encryption error: {e}")

    def decrypt_text(self):
        encoded = self.output_text.get("1.0", tk.END).strip() or self.input_text.get("1.0", tk.END).strip()
        if not encoded:
            self.show_status("Please enter base64-encoded text to decrypt.")
            return
        try:
            decrypted = self.kasper.decrypt(base64.b64decode(encoded), self.encryption_key)
            self.output_text.delete("1.0", tk.END)
            self.output_text.insert("1.0", decrypted.decode('utf-8'))
            self.show_status("Text decrypted successfully!")
        except Exception as e:
            self.show_status(f"Decryption error: {e}")

    def clear_text(self):
        self.input_text.delete("1.0", tk.END)
        self.output_text.delete("1.0", tk.END)
        self.show_status("Text cleared.")

    def encrypt_file(self):
        path = self.file_path_var.get()
        if not (path and os.path.isfile(path)):
            self.show_status("Please select a valid file.")
            return
        if not messagebox.askyesno("Confirm Overwrite", f"This will overwrite:\n{path}\n\nProceed?"):
            self.show_status("Cancelled.")
            return
        try:
            with open(path, 'rb') as f:
                data = f.read()
            encrypted = self.kasper.encrypt(data, self.encryption_key)
            with open(path, 'wb') as f:
                f.write(self.salt + encrypted)
            self.show_status(f"File encrypted: {path}")
            if messagebox.askyesno("Complete", "File encrypted.\nOpen folder?"):
                self.open_folder(os.path.dirname(path))
        except Exception as e:
            self.show_status(f"Encryption error: {e}")

    def decrypt_file(self):
        path = self.file_path_var.get()
        if not (path and os.path.isfile(path)):
            self.show_status("Select a valid file.")
            return
        if not messagebox.askyesno("Confirm Overwrite", f"This will overwrite:\n{path}\n\nProceed?"):
            self.show_status("Cancelled.")
            return
        try:
            with open(path, 'rb') as f:
                data = f.read()
            if len(data) < 16:
                self.show_status("Invalid file.")
                return
            key, _ = self.kasper.derive_encryption_key(self.shared_secret, data[:16])
            decrypted = self.kasper.decrypt(data[16:], key)
            with open(path, 'wb') as f:
                f.write(decrypted)
            self.show_status(f"File decrypted: {path}")
            if messagebox.askyesno("Complete", "File decrypted.\nOpen folder?"):
                self.open_folder(os.path.dirname(path))
        except Exception as e:
            self.show_status(f"Decryption error: {e}")

    def open_folder(self, folder):
        if platform.system() == "Windows":
            os.startfile(folder)
        elif platform.system() == "Darwin":
            subprocess.Popen(["open", folder])
        else:
            subprocess.Popen(["xdg-open", folder])

    def show_status(self, message):
        if hasattr(self, 'status_text'):
            self.status_text.insert(tk.END, message + "\n")
            self.status_text.see(tk.END)
        if hasattr(self, 'text_status_text'):
            self.text_status_text.insert(tk.END, message + "\n")
            self.text_status_text.see(tk.END)

    def create_footer(self):
        p = self.PALETTE
        footer = tk.Frame(self.root, height=64, bg=p["navy_dark"])
        footer.pack(fill=tk.X, side=tk.BOTTOM)
        footer.pack_propagate(False)
        tk.Label(
            footer, text="KASPER ENCRYPTION SYSTEM", bg=p["navy_dark"], fg="#ffffff",
            font=("Helvetica", 13, "bold")
        ).pack(pady=(10, 0))
        tk.Label(
            footer, text="Developed by Hamdan", bg=p["navy_dark"], fg="#c7d1de",
            font=("Helvetica", 10, "italic")
        ).pack()

    def handle_generate_rsa_keys(self):
        try:
            priv_key, pub_key = self.signature_manager.generate_keys()
            priv_file, pub_file = "rsa_private_key.pem", "rsa_public_key.pem"
            self.signature_manager.save_key_to_pem(priv_key, priv_file)
            self.signature_manager.save_key_to_pem(pub_key, pub_file)
            messagebox.showinfo("Success", f"Keys saved:\n{priv_file}\n{pub_file}")
        except Exception as e:
            messagebox.showerror("Error", f"Key generation failed: {e}")

    def handle_sign_file(self):
        priv_path = filedialog.askopenfilename(title="Select Private Key", filetypes=[("PEM files", "*.pem")])
        if not priv_path:
            return
        file_path = filedialog.askopenfilename(title="Select File to Sign")
        if not file_path:
            return
        try:
            priv_key = self.signature_manager.load_private_key(priv_path)
            sig = self.signature_manager.sign_file(priv_key, file_path)
            self.signature_display_text.delete("1.0", tk.END)
            self.signature_display_text.insert("1.0", base64.b64encode(sig).decode())

            sig_file = file_path + ".sig"
            with open(sig_file, 'wb') as f:
                f.write(sig)

            messagebox.showinfo("Success", f"File signed successfully!\nSignature saved to: {sig_file}")
        except Exception as e:
            messagebox.showerror("Error", f"Signing failed: {e}")

    def handle_verify_file(self):
        pub_path = filedialog.askopenfilename(title="Select Public Key", filetypes=[("PEM files", "*.pem")])
        if not pub_path:
            return
        file_path = filedialog.askopenfilename(title="Select Original File")
        if not file_path:
            return

        sig_path = file_path + ".sig"
        if not os.path.exists(sig_path):
            sig_path = filedialog.askopenfilename(title="Select Signature File", filetypes=[("Signature", "*.sig"), ("All files", "*.*")])
            if not sig_path:
                return

        try:
            with open(sig_path, 'rb') as f:
                sig = f.read()
            pub_key = self.signature_manager.load_public_key(pub_path)
            is_valid = self.signature_manager.verify_signature(pub_key, file_path, sig)
            if is_valid:
                self.verify_status_label.config(text="VALID SIGNATURE ✅", foreground="green")
                messagebox.showinfo("Verification Result", "✅ SIGNATURE IS VALID")
            else:
                self.verify_status_label.config(text="INVALID SIGNATURE ❌", foreground="red")
                messagebox.showwarning("Verification Result", "❌ SIGNATURE IS INVALID")
        except Exception as e:
            messagebox.showerror("Error", f"Verification failed: {e}")
            self.verify_status_label.config(text="FAILED ❌", foreground="red")


if __name__ == "__main__":
    root = tk.Tk()
    app = KasperEncryptionGUI(root)
    root.mainloop()
