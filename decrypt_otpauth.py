import base64
import getpass
import hashlib
import plistlib
from enum import Enum
from typing import Any
from urllib.parse import quote

import click
from bpylist2 import archiver
from bpylist2.archiver import ArchivedObject
from Crypto.Cipher import AES
from rncryptor import RNCryptor, bord


class Type(Enum):
    Unknown = 0
    HOTP = 1
    TOTP = 2

    @property
    def uri_value(self):
        if self.value == 0:
            return "unknown"
        if self.value == 1:
            return "hotp"
        if self.value == 2:
            return "totp"


class Algorithm(Enum):
    Unknown = 0
    SHA1 = 1  # Used in case of Unknown
    SHA256 = 2
    SHA512 = 3
    MD5 = 4

    @property
    def uri_value(self):
        if self.value == 0:
            return "sha1"
        if self.value == 1:
            return "sha1"
        if self.value == 2:
            return "sha256"
        if self.value == 3:
            return "sha512"
        if self.value == 4:
            return "md5"


class MutableString:
    @staticmethod
    def decode_archive(archive: ArchivedObject):
        return archive.decode("NS.string")


class MutableData:
    @staticmethod
    def decode_archive(archive: ArchivedObject):
        return bytes(archive.decode("NS.data"))


class OTPFolder:
    name = None
    accounts = None

    def __init__(self, name, accounts):
        self.name = name
        self.accounts = accounts

    def __repr__(self):
        return f"<OTPFolder: {self.name}>"

    @staticmethod
    def decode_archive(archive: ArchivedObject):
        name = archive.decode("name")
        accounts = archive.decode("accounts")
        return OTPFolder(name, accounts)


class OTPAccount:
    label: str
    issuer: str
    secret: bytes
    type: Type
    algorithm: Algorithm
    digits: int
    counter: int
    period: int
    refDate: int
    idx: int
    icon: bytes | None

    def __init__(
        self,
        label: str,
        issuer: str,
        secret: bytes,
        type: Type,
        algorithm: Algorithm,
        digits: int,
        counter: int,
        period: int,
        refDate: int,
        idx: int,
        icon: bytes | None,
    ):
        self.label = label
        self.issuer = issuer
        self.secret = secret
        self.type = type
        self.algorithm = algorithm
        self.digits = digits
        self.counter = counter
        self.period = period
        self.refDate = refDate
        self.idx = idx
        self.icon = icon

    def __repr__(self):
        return f"<OTPAccount: {self.issuer} ({self.label})>"

    @staticmethod
    def decode_archive(archive: ArchivedObject):
        label = archive.decode("label")
        issuer = archive.decode("issuer")
        secret = bytes(archive.decode("secret"))
        type = Type(archive.decode("type"))
        algorithm = Algorithm(archive.decode("algorithm"))
        digits = archive.decode("digits")
        counter = archive.decode("counter")
        period = archive.decode("period")
        refDate = archive.decode("refDate")
        idx = archive.decode("ID")
        icon = archive.decode("icon")
        return OTPAccount(
            label,
            issuer,
            secret,
            type,
            algorithm,
            digits,
            counter,
            period,
            refDate,
            idx,
            icon,
        )

    @staticmethod
    def from_dict(in_dict: dict[str, Any]):
        label = in_dict["label"]
        issuer = in_dict["issuer"]
        secret = bytes(in_dict["secret"])
        type = Type(in_dict["type"])
        algorithm = Algorithm(in_dict["algorithm"])
        digits = in_dict["digits"]
        counter = in_dict["counter"]
        period = in_dict["period"]
        refDate = in_dict["refDate"]
        idx = in_dict.get("ID", "")
        icon = in_dict.get("icon")

        return OTPAccount(
            label,
            issuer,
            secret,
            type,
            algorithm,
            digits,
            counter,
            period,
            refDate,
            idx,
            icon,
        )

    def otp_uri(self):
        otp_type = self.type.uri_value
        otp_label = quote(f"{self.issuer}:{self.label}")
        otp_parameters = {
            "secret": base64.b32encode(self.secret).decode("utf-8").rstrip("="),
            "algorithm": self.algorithm.uri_value,
            "period": self.period,
            "digits": self.digits,
            "issuer": self.issuer,
            "counter": self.counter,
        }
        otp_parameters = "&".join(
            [f"{str(k)}={quote(str(v))}" for (k, v) in otp_parameters.items() if v]
        )
        return f"otpauth://{otp_type}/{otp_label}?{otp_parameters}"


archiver.update_class_map({"NSMutableData": MutableData})
archiver.update_class_map({"NSMutableString": MutableString})
archiver.update_class_map({"ACOTPFolder": OTPFolder})
archiver.update_class_map({"ACOTPAccount": OTPAccount})


class RawRNCryptor(RNCryptor):
    def post_decrypt_data(self, data):
        """Remove useless symbols which
        appear over padding for AES (PKCS#7)."""
        data = data[: -bord(data[-1])]
        return data


class DangerousUnarchive(archiver.Unarchive):
    def decode_object(self, index):
        if index == 0:
            return None

        obj = self.unpacked_uids.get(index)

        if obj is not None:
            return obj

        raw_obj = self.objects[index]

        # if obj is a (semi-)primitive type (e.g. str)
        if not isinstance(raw_obj, dict):
            return raw_obj

        class_uid = raw_obj.get("$class")
        if not isinstance(class_uid, plistlib.UID):
            raise archiver.MissingClassUID(raw_obj)

        klass = self.class_for_uid(class_uid)
        obj = klass.decode_archive(archiver.ArchivedObject(raw_obj, self))

        self.unpacked_uids[index] = obj
        return obj


@click.group()
def cli():
    pass


@cli.command()
@click.option(
    "--encrypted-otpauth-account",
    help="path to your encrypted OTP Auth account (.otpauth)",
    required=True,
    type=click.File("rb"),
)
def decrypt_account(encrypted_otpauth_account):
    # Get IV and key for wrapping archive
    iv = bytes(16)
    key = hashlib.sha256("OTPAuth".encode("utf-8")).digest()

    # Decrypt wrapping archive
    data = AES.new(key, AES.MODE_CBC, iv).decrypt(encrypted_otpauth_account.read())
    data = data[: -data[-1]]

    # Decode wrapping archive
    archive = archiver.Unarchive(data).top_object()
    assert isinstance(archive, dict)
    version = archive.get("Version")

    password = getpass.getpass(
        f"Password for export file {encrypted_otpauth_account.name}: "
    )
    if version == 1.1:
        data = decrypt_account_11(archive, password)
    elif version == 1.2:
        data = decrypt_account_12(archive, password)
    else:
        click.echo(f'Encountered unknow file version: {archive["Version"]}')
        return

    archive = DangerousUnarchive(data).top_object()
    assert isinstance(archive, dict), "Decoded account is not a dictionary"

    account = OTPAccount.from_dict(archive)
    print(account.otp_uri())


def decrypt_account_11(archive, password) -> bytes:
    # Get IV and key for actual archive
    iv = hashlib.sha1(archive["IV"]).digest()[:16]
    salt = archive["Salt"]
    key = hashlib.sha256((salt + "-" + password).encode("utf-8")).digest()

    # Decrypt actual archive
    data = AES.new(key, AES.MODE_CBC, iv).decrypt(archive["Data"])
    data = data[: -data[-1]]

    return data


def decrypt_account_12(archive, password) -> bytes:
    data = RawRNCryptor().decrypt(archive["Data"], password)
    assert isinstance(data, bytes)
    assert data is not None, "Decryption failed. Wrong password?"
    return data


@cli.command()
@click.option(
    "--encrypted-otpauth-backup",
    help="path to your encrypted OTP Auth backup (.otpauthdb)",
    required=True,
    type=click.File("rb"),
)
@click.option(
    "--export-icon-path",
    help="path to export icons to (if not specified, icons won't be exported)",
    required=False,
    type=click.Path(file_okay=False, dir_okay=True, writable=True),
)
def decrypt_backup(encrypted_otpauth_backup, export_icon_path):
    # Get IV and key for wrapping archive
    iv = bytes(16)
    key = hashlib.sha256("Authenticator".encode("utf-8")).digest()

    # Decrypt wrapping archive
    data = AES.new(key, AES.MODE_CBC, iv).decrypt(encrypted_otpauth_backup.read())
    data = data[: -data[-1]]

    # Decode wrapping archive
    archive = archiver.Unarchive(data).top_object()
    assert isinstance(archive, dict)

    version = archive.get("Version")

    password = getpass.getpass(
        f"Password for backup file {encrypted_otpauth_backup.name}: "
    )
    if version == 1.0:
        data = decrypt_backup_10(archive, password)
    elif version == 1.1:
        data = decrypt_backup_11(archive, password)
    else:
        click.echo(f'Encountered unknow file version: {archive["Version"]}')
        return

    archive = DangerousUnarchive(data).top_object()
    assert isinstance(archive, dict), "Decoded backup is not a dictionary"

    accounts = [account for folder in archive["Folders"] for account in folder.accounts]

    for idx, account in enumerate(accounts):
        icon = account.icon
        if isinstance(icon, bytes) and export_icon_path:
            with open(f"{export_icon_path}/icon_{idx}.png", "wb") as icon_file:
                icon_file.write(icon)

        print(account.otp_uri())


def decrypt_backup_10(archive: dict, password: str) -> bytes:
    # Get IV and key for actual archive
    iv = hashlib.sha1(archive["IV"].encode("utf-8")).digest()[:16]
    salt = archive["Salt"]
    key = hashlib.sha256((salt + "-" + password).encode("utf-8")).digest()

    # Decrypt actual archive
    data = AES.new(key, AES.MODE_CBC, iv).decrypt(archive["WrappedData"])
    data = data[: -data[-1]]
    return data


def decrypt_backup_11(archive: dict, password: str) -> bytes:
    # Decrypt using RNCryptor
    data = RawRNCryptor().decrypt(archive["WrappedData"], password)
    assert isinstance(data, bytes)
    assert data is not None, "Decryption failed. Wrong password?"

    return data


if __name__ == "__main__":
    cli()
