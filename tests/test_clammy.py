from io import BytesIO

from clammy import ClamAVDaemon, exceptions

import pytest

# The EICAR test file https://en.wikipedia.org/wiki/EICAR_test_file
EICAR = r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"


@pytest.fixture()
def clamav_daemon():
    return ClamAVDaemon(unix_socket="/var/run/clamav/clamd.ctl")


def test_ping(clamav_daemon):
    assert clamav_daemon.ping() == "PONG"


def test_cannot_connect():
    with pytest.raises(exceptions.ConnectionError):
        ClamAVDaemon(unix_socket="/tmp/404").ping()


def test_version(clamav_daemon):
    assert clamav_daemon.version().startswith("ClamAV")


def test_reload(clamav_daemon):
    assert clamav_daemon.reload() == "RELOADING"


def test_scan(clamav_daemon, tmpdir):
    p = tmpdir.join("eicar.txt")
    p.write(EICAR)

    assert clamav_daemon.scan(str(p)) == {
        str(p): ("FOUND", "winnow.malware.test.eicar.com.UNOFFICIAL")
    }


def test_multiscan(clamav_daemon, tmpdir):
    p = tmpdir.join("eicar.txt")
    p.write(EICAR)

    assert clamav_daemon.scan(str(tmpdir)) == {
        str(p): ("FOUND", "winnow.malware.test.eicar.com.UNOFFICIAL")
    }


def test_instream(clamav_daemon):
    assert clamav_daemon.instream(BytesIO(EICAR.encode("utf-8"))) == {
        "stream": ("FOUND", "winnow.malware.test.eicar.com.UNOFFICIAL")
    }
