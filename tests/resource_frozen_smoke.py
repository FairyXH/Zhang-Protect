import hashlib
import json
import tempfile

from README import READMEf
from xzzip7 import zip7f
from ZhangProxyLauncher import ZhangProxyLauncherf
from resource_loader import write_resource


def main():
    result = {}
    for resource in (READMEf, zip7f, ZhangProxyLauncherf):
        digest = hashlib.sha256()
        with tempfile.TemporaryFile() as output:
            write_resource(output, resource)
            length = output.tell()
            output.seek(0)
            while chunk := output.read(1024 * 1024):
                digest.update(chunk)
        result[resource.name] = {"size": length, "sha256": digest.hexdigest()}
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
