"""Prove elapsed-time limits with a real local connection and safe cancellation."""

import socket
import time

import pytest

from openhound_collector_common.clients.deadline import Deadline


def test_deadline_interrupts_a_waiting_socket():
    reader, writer = socket.socketpair()
    started = time.monotonic()
    try:
        with pytest.raises(TimeoutError, match="deadline expired"):
            with Deadline.after(0.1).bound_socket(reader):
                # No receive timeout: only the elapsed-time guard can stop this.
                reader.recv(1)
        assert time.monotonic() - started < 3
        assert reader.fileno() == -1
    finally:
        reader.close()
        writer.close()


def test_completed_operation_cancels_its_socket_interrupt():
    reader, writer = socket.socketpair()
    try:
        deadline = Deadline.after(0.1)
        with deadline.bound_socket(reader):
            writer.sendall(b"first")
            assert reader.recv(5) == b"first"
        # Waiting past the original deadline proves the retained connection is
        # usable; checking Timer.cancel alone would only mirror implementation.
        time.sleep(0.15)
        writer.sendall(b"second")
        assert reader.recv(6) == b"second"
        with pytest.raises(TimeoutError):
            deadline.remaining()
    finally:
        reader.close()
        writer.close()


@pytest.mark.parametrize("seconds", [0, -1])
def test_nonpositive_connection_budget_is_rejected(seconds):
    with pytest.raises(ValueError, match="positive"):
        Deadline.after(seconds)
