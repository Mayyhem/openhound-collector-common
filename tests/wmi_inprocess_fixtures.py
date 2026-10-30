"""Inert network transport for exercising the real impacket shared credential map."""

from types import SimpleNamespace

from impacket.dcerpc.v5 import dcomrt
from impacket.dcerpc.v5.dcom import wmi


class InertSocket:
    def shutdown(self, how):
        pass  # This controlled provider never opens an actual socket.

    def close(self):
        pass  # There is no external connection to close.


class InertTransport:
    def __init__(self):
        self.credentials = ()
        self.socket = InertSocket()

    def set_credentials(self, *credentials):
        self.credentials = credentials

    def set_kerberos(self, *settings):
        pass  # No authentication exchange occurs in this offline transport.

    def get_dce_rpc(self):
        transport = self

        class Rpc:
            def set_auth_level(self, level):
                pass  # Keep the real constructor's call; there is no wire state.

            def connect(self):
                pass  # Deliberately replaces the network boundary only.

            def disconnect(self):
                pass  # The real DCOM disconnect still removes shared entries.

            def get_credentials(self):
                return transport.credentials

            def get_rpc_transport(self):
                return transport

        return Rpc()

    def get_socket(self):
        return self.socket


def install_provider(monkeypatch, before_row=lambda: None):
    """Keep real constructors/maps, substituting network and remote WMI responses."""
    import socket

    def refuse_network(*args, **kwargs):
        raise AssertionError("This credential check must never connect to a target")

    monkeypatch.setattr(socket.socket, "connect", refuse_network)
    monkeypatch.setattr(
        dcomrt.transport, "DCERPCTransportFactory", lambda binding: InertTransport()
    )
    monkeypatch.setattr(
        dcomrt.DCOMConnection,
        "CoCreateInstanceEx",
        lambda connection, *args: connection,
    )

    class Login:
        def __init__(self, connection):
            self.connection = connection

        def NTLMLogin(self, namespace, *args):
            connection = self.connection

            class Enumerator:
                has_returned = False

                def Next(self, timeout, count):
                    if self.has_returned:
                        raise RuntimeError("S_FALSE")
                    self.has_returned = True
                    before_row()
                    # This is the real process-wide lookup that previously let
                    # another connection replace this session's credentials.
                    identity = connection.get_dce_rpc().get_credentials()[0]
                    return [
                        SimpleNamespace(
                            getProperties=lambda: {"identity": {"value": identity}}
                        )
                    ]

                def RemRelease(self):
                    pass  # There is no actual remote reference in this fake.

            return SimpleNamespace(ExecQuery=lambda *args, **kwargs: Enumerator())

        def RemRelease(self):
            pass  # There is no actual remote reference in this fake.

    monkeypatch.setattr(wmi, "IWbemLevel1Login", Login)
