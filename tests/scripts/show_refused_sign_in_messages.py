"""Print what a refused directory sign-in logs while the run's stop signal is connected.

Run it from the shared library's folder:

    uv run --locked python tests/scripts/show_refused_sign_in_messages.py

A collector links its run's stop signal to every read's time limit once collection has
started, as the SQL collector does. This signs in once with a wrong password to a stand-in
domain controller that refuses it with the lab's reply (data 52e), then prints the warnings
and errors that were logged and how the sign-in ended. Nothing is contacted: network name
lookups are turned off first, and the stand-in answers in place of the real connection.
"""

import logging
import socket
import sys
import threading

from ldap3.core.exceptions import LDAPBindError

from openhound_collector_common.clients import ad
from openhound_collector_common.clients.credential_guard import CredentialGuard
from openhound_collector_common.clients.operations import ReadControl

LAB_REFUSAL = (
    "invalidCredentials: 8009030C: LdapErr: DSID-0C0906B0, comment: "
    "AcceptSecurityContext error, data 52e, v4f7c"
)


def no_network(*args, **kwargs):
    raise AssertionError("This script must not contact anything")


def refuse(self, *, host, attempt):
    raise LDAPBindError(LAB_REFUSAL)


def main() -> None:
    socket.getaddrinfo = no_network
    socket.create_connection = no_network
    ad.AdClient._open_connection = refuse
    # Log to the same stream as print(), so the lines stay in order.
    logging.basicConfig(
        level=logging.WARNING,
        format="  %(levelname)-8s %(message)s",
        stream=sys.stdout,
    )

    stop = threading.Event()
    guard = CredentialGuard()
    guard.add_stop_action(stop.set)  # Connected, as it is once collection has started.
    client = ad.AdClient(
        "example.test",
        dc="dc.example.test",
        auth=ad.LdapAuth(username="EXAMPLE\\reader", password="deliberately-wrong"),
        read_control=ReadControl(30, stop_event=stop),
        credential_guard=guard,
    )
    print("Logged:")
    try:
        client.bind()
    except Exception as error:
        print(f"The sign-in ended with: {type(error).__name__}: {error}")
    print(f"Run-wide record: rejected by {guard.rejected_by}")
    print(f"Run's stop signal set: {'yes' if stop.is_set() else 'no'}")


if __name__ == "__main__":
    main()
