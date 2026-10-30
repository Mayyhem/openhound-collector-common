# Current-user WMI in collector worker threads

Status: approved by the owner on October 26, 2026; implementation added to
`clients/wmi.py`, with grouped verification completed as described below.

The feature plan enables the existing current-user WMI client. Inspection found
that its `_PyWin32Backend.connect` calls `win32com.client.Dispatch` without
initializing Windows COM on the calling thread. Collector workers are new
threads; the main thread's initialization does not initialize them. This can
make the newly enabled current-user path fail before any WMI query.

Proposed correction in `clients/wmi.py`: initialize COM on the connecting
thread, remember that thread, release its namespace/locator objects, and balance
that initialization when the same thread closes the backend. If dispatch fails,
release the initialization immediately. Repeated connect/close calls must be
safe. Explicit-credential impacket operation remains unchanged.

This belongs in common because that repository owns the backend and both
collectors use it. A collector-only initializer would leave the shared client's
thread requirement hidden from other callers. No dependency is added: pywin32 is
already declared. Check initialization/cleanup with mocked Windows calls, then
exercise current-user WMI on an authorized Windows lab host at the larger
credentials checkpoint. Proxy mode continues to reject native current-user WMI.

The implementation uses `CoInitializeEx(COINIT_MULTITHREADED)` on each connecting
worker. A thread already initialized with another Windows COM model can retain
that model; the backend does not release the caller's initialization. Other
initialization errors propagate. WMI object creation failure balances any new
initialization immediately. Closing or using the backend on another thread is
an explicit error rather than an unsafe cleanup attempt. Explicit-credential
impacket clients retain their existing implementation.

Source: [Microsoft COM thread initialization guidance](https://learn.microsoft.com/en-us/windows/win32/learnwin32/initializing-the-com-library).

Verification: five mocked initialization/cleanup/thread-ownership cases passed.
On Windows, two actual worker threads each created a native WMI locator and
balanced their own COM initialization. The complete shared suite passed 254
tests with one explicit Python-version skip before adding the graph evidence
helper. The later 28-test evidence/WMI/proxy/network selection and shared lint
and type checks also passed. Remote native collection remains part of the final
live acceptance; local object creation alone is not that acceptance.
