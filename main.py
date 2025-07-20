import json, re, sqlite3
from typing import *

from fastapi import FastAPI, status, Depends, Query, Request, Response
from fastapi.encoders import jsonable_encoder
from fastapi.responses import HTMLResponse, PlainTextResponse, RedirectResponse

from pydantic import BaseModel, Field, BeforeValidator, Base64Str
from pydantic.networks import IPv4Address, IPv6Address

RE_DOMAIN = re.compile(r"^[a-z0-9\.-]+$", re.IGNORECASE)

app = FastAPI()

def get_db():
    db = sqlite3.connect('records.db')
    try:
        yield db
    finally:
        db.close()

@app.on_event("startup")
def on_startup():
    db = sqlite3.connect('records.db')
    #with get_db() as db:
    db.execute("""CREATE TABLE IF NOT EXISTS records(
        apex TEXT NOT NULL,
        subdomain TEXT NOT NULL,
        type TEXT NOT NULL,
        value TEXT NOT NULL,
        UNIQUE(apex,subdomain,type,value)) STRICT
    """)
    db.commit()

def parse_comma_list(value: list|str) -> list:
    if isinstance(value, list):
        return value
    else:
        return value.split(",")

class ARecord(BaseModel):
    record_type: Literal['A']
    record_val: IPv4Address

class AaaaRecord(BaseModel):
    record_type: Literal['AAAA']
    record_val: IPv6Address

class CnameRecord(BaseModel):
    record_type: Literal['CNAME']
    record_val: Annotated[str, Field(min_length=3, max_length=255, pattern=RE_DOMAIN)]

class MxRecord(BaseModel):
    record_type: Literal['MX']
    class MXVal(BaseModel):
        priority: Annotated[int, Field(ge=0, le=0xFFFF)]
        host: str
        def __str__(cls):
            return f"{cls.priority} {cls.host}"
    record_val: MXVal

#	IN HTTPS 1 . alpn="h2,h3,http/1.1" ipv4hint="135.181.87.135" ipv6hint="2a01:4f9:c012:dd04:0:0:0:1"
class HttpsRecord(BaseModel):
    record_type: Literal['HTTPS']
    class HTTPSVal(BaseModel):
        priority: Annotated[int, Field(ge=0, le=0xFFFF, examples=['1'])]
        hostname: Annotated[str, Field(max_length=255, pattern=RE_DOMAIN, examples=['.'])]
        alpn: Optional[Annotated[str, Field(min_length=1, max_length=255)]] = None  # TODO: pattern=?
        port: Optional[Annotated[int, Field(ge=0, le=0xFFFF, examples=['443'])]] = None
        #ipv4hint: Optional[Annotated[List[IPv4Address], BeforeValidator(parse_comma_list)]] = None
        #ipv6hint: Optional[list[IPv6Address]] = None
        ech: Optional[Base64Str] =  None
        def __str__(cls):
            extra = ""
            if cls.alpn: extra += f" {alpn=}"
            if cls.port: extra += f" {port=}"
            #if cls.ipv4hint: extra += f" {ipv4hint=}"
            #if cls.ipv6hint: extra += f" {ipv6hint=}"
            if cls.ech: extra += f" {ech=}"  # TODO: b64encode (iitauto decodes)
            return f'{cls.priority} {cls.hostname}{extra}'
    record_val: HTTPSVal

class CaaRecord(BaseModel):
    record_type: Literal['CAA']
    class CAAVal(NamedTuple):
        flags: Annotated[int, Field(ge=0, le=255)]
        tag: Literal['issue', 'issuewild', 'issuemail', 'iodef']
        value: Annotated[str, Field(min_length=0, max_length=256)]
        def __str__(cls):
            # TODO: escape cls.value with quotes
            value = cls.value.replace("\\", "\\\\").replace('"', '\\"')
            return f'{cls.flags} {cls.tag} "{value}"'
    record_val: CAAVal
    #	IN CAA 0 iodef "mailto:caa-violation@xn--sb-lka.org"
    #	IN CAA 128 issue "letsencrypt.org; accounturi=https://acme-v02.api.letsencrypt.org/acme/acct/85697055"

class SshfpRecord(BaseModel):
    record_type: Literal['SSHFP']
    class SSHFPVal(BaseModel):
        hash_type: Literal['SHA-1', 'SHA-256']
        algorithm: Literal['RSA', 'Ed25519', 'Ed448']
        fingerprint: Annotated[str, Field(min_length=40, max_length=64, pattern=r'[0-9A-F]+')]
        def __str__(cls):
            hash_type = {'SHA-1': 1, 'SHA-256': 2}[cls.hash_type]
            key_type  = {'RSA': 1, 'Ed25519': 4, 'Ed448': 6}[cls.algorithm]
            return f"{key_type} {hash_type} {cls.fingerprint}"
    record_val: SSHFPVal

#class TlsaRecord(BaseModel):
#    record_type: Literal['TLSA']
#    class Selector(IntEnum):
#        FullCertificate = 0
#        SubjectPublicKeyInfo = 1
#    class MatchingType(IntEnum):
#        ExactMatch = 0
#        SHA256     = 1
#        SHA512     = 2
#    class TlsaVal(NamedTuple):
#        selector: Selector
#        tag: Literal['issue', 'issuewild', 'issuemail', 'iodef']
#        value: Annotated[str, Field(min_length=0, max_length=256)]
#        def __str__(cls):
#            # TODO: escape cls.value with quotes
#            value = cls.value.replace("\\", "\\\\").replace('"', '\\"')
#            return f'{cls.flags} {cls.tag} "{value}"'
#    record_val: CaaVal | List[CaaVal]
#    #hash_type: Literal['SHA-1', 'SHA-256']
#
#    #def __str__(cls):
#    #    #hash_type = {'SHA-1': 1, 'SHA-256': 2}[cls.hash_type]
#    #    return f"{key_type} {hash_type} {cls.fingerprint}"

class TxtRecord(BaseModel):
    record_type: Literal['TXT']
    # TODO: quotes around? escape \\?
    record_val: Annotated[str, Field(min_length=1, max_length=256)]

class Record(BaseModel):
    # TODO: pattern/validator for domain (e.g. check using HttpUrl and extract .domain)
    apex: Annotated[str, Field(example="example.com", min_length=3, max_length=255, pattern=RE_DOMAIN)]
    subdomain: Annotated[str, Field(example="@", min_length=1, max_length=255)]  # TODO: pattern
    #ttl: Annotated[int, Field(default=3600, ge=300, le=0xffff)]  # TODO: max?
    record: ARecord | AaaaRecord | CaaRecord | CnameRecord | HttpsRecord | MxRecord | SshfpRecord | TxtRecord = Field(discriminator='record_type')
    #def __str__(cls):
    #    val = cls.value.record_val if type(cls.value.record_val) == list else [cls.value.record_val]
    #    return '\n'.join(f"{cls.subdomain} {cls.ttl} IN {cls.value.record_type} {v}" for v in val)

def get_record_val(data: Record) -> str | dict:
    j = data.model_dump(mode='json')
    return j['record']['record_val']

@app.get("/", response_class=HTMLResponse)
def read_root(response: Response):
    #response.status_code = status.HTTP_201_CREATED
    #return """<html>HELLO</html>"""
    return RedirectResponse("https://pyjam.as/portal")

@app.put("/dns/", response_class=PlainTextResponse)
def update_record(data: Record, db = Depends(get_db)):
    row = (data.apex, data.subdomain, data.record.record_type, get_record_val(data))
    print(row)
    try:
        db.execute("INSERT INTO records(apex, subdomain, type, value) VALUES(?, ?, ?, ?)", row).fetchone()
    except sqlite3.IntegrityError as ex:
        pass
    # TODO: status code?
    db.commit()
    return str(data)

@app.delete("/dns/", response_class=PlainTextResponse)
def delete_record(data: Record, db = Depends(get_db)):
    #DATA apex='example.com' subdomain='@' record=ARecord(record_type='A', record_val=IPv4Address('4.3.2.1'))
    row = (data.apex, data.subdomain, data.record.record_type, get_record_val(data))
    res = db.execute("DELETE FROM records WHERE apex=? AND subdomain=? AND type=? AND value=?", row)
    db.commit()
    # TODO: status code?
    return f'Affected: {res.rowcount}'

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)
