from typing import NamedTuple

class Header(NamedTuple):
    # offsets ...
    # fields ...
    pass

def wrap(rawReq) -> None: # maybe some other params
    pass
    
def parse(rawResp) -> Header:
    # hanlde incorrect checksum: raise exception?
    pass