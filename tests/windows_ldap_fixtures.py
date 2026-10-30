"""Inert Windows LDAP API with real ctypes buffers and explicit cleanup records."""

import ctypes

from openhound_collector_common.clients import windows_ldap as native


class WindowsLdapApi:
    """Supply controlled pages while exercising the adapter's actual pointer decoding."""

    def __init__(self, pages):
        self.pages = list(pages)
        self.options = {}
        self.cleaned = []
        self.buffers = []
        self.rows = {}
        self.page_entries = {}
        self.attribute_positions = {}
        self.page = 0
        self.bind_code = 0
        self.cleanup_code = 0
        self.requested_pages = []
        self.has_tls = False

    def ldap_initW(self, host, port):
        self.destination = (host, port)
        return 1

    def ldap_sslinitW(self, host, port, secure):
        self.has_tls = bool(secure)
        return self.ldap_initW(host, port)

    def ldap_set_optionW(self, handle, option, value):
        self.options[option] = value._obj.value
        return 0

    def ldap_get_optionW(self, handle, option, value):
        value._obj.value = -1 if option == 0x01 else 0
        return 0

    def ldap_connect(self, handle, timeout):
        return 0

    def ldap_bind_sW(self, handle, username, credentials, method):
        assert username is None and credentials is None and method == 0x486
        return self.bind_code

    def ldap_search_init_pageW(self, *args):
        return 2

    def ldap_get_next_page_s(
        self, handle, search, timeout, page_size, estimated, results
    ):
        self.requested_pages.append(page_size)
        code, rows = self.pages[self.page]
        self.page += 1
        page_id = 100 * self.page
        entries = []
        for index, row in enumerate(rows):
            entry_id = page_id + index + 1
            entries.append(entry_id)
            self.rows[entry_id] = row
        self.page_entries[page_id] = entries
        results._obj.value = page_id
        estimated._obj.value = 0  # A server estimate of zero is not end-of-search.
        return code

    def ldap_first_entry(self, handle, results):
        entries = self.page_entries[results.value]
        return entries[0] if entries else None

    def ldap_next_entry(self, handle, entry):
        for entries in self.page_entries.values():
            if entry in entries:
                index = entries.index(entry) + 1
                return entries[index] if index < len(entries) else None
        raise AssertionError("Unknown test entry")

    def _text(self, value):
        buffer = ctypes.create_unicode_buffer(value)
        self.buffers.append(buffer)
        return ctypes.addressof(buffer)

    def ldap_get_dnW(self, handle, entry):
        return self._text(self.rows[entry][0])

    def ldap_first_attributeW(self, handle, entry, iterator):
        iterator._obj.value = entry
        self.attribute_positions[entry] = 0
        names = list(self.rows[entry][1])
        return self._text(names[0]) if names else None

    def ldap_next_attributeW(self, handle, entry, iterator):
        self.attribute_positions[entry] += 1
        index = self.attribute_positions[entry]
        names = list(self.rows[entry][1])
        return self._text(names[index]) if index < len(names) else None

    def ldap_get_values_lenW(self, handle, entry, name):
        values = self.rows[entry][1][name]
        pointers = []
        for value in values:
            buffer = ctypes.create_string_buffer(value)
            record = native._Berval(len(value), ctypes.addressof(buffer))
            self.buffers.extend((buffer, record))
            pointers.append(ctypes.pointer(record))
        array = (ctypes.POINTER(native._Berval) * (len(pointers) + 1))(*pointers, None)
        self.buffers.append(array)
        return array

    def ldap_value_free_len(self, values):
        self.cleaned.append("attribute-values")
        return 0

    def ldap_memfreeW(self, pointer):
        self.cleaned.append("text")

    def ber_free(self, iterator, free_buffer):
        self.cleaned.append("attribute-iterator")

    def ldap_msgfree(self, results):
        self.cleaned.append("page")
        return 0

    def ldap_search_abandon_page(self, handle, search):
        self.cleaned.append("search")
        return self.cleanup_code

    def ldap_unbind(self, handle):
        self.cleaned.append("connection")
        return 0

    def LdapGetLastError(self):
        return 0
