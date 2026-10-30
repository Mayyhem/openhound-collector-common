"""Explain suspicious parsed arguments using the caller's options and redaction rules."""

from collections.abc import Callable, Collection, Mapping, Sequence


def suspicious_argument_warnings(
    argv: Sequence[str],
    *,
    short_options: Mapping[str, str],
    long_options: Collection[str],
    sensitive_options: Collection[str],
    is_sensitive_value: Callable[[str], bool] | None = None,
) -> list[str]:
    """Return safe typo hints without reparsing or changing the command.

    Click can interpret -dc as -d c. The caller provides the options that take
    values and decides which values are sensitive, including inline credentials.
    Warnings are data: the caller chooses its existing logger and output policy.
    """

    def display(option: str, value: str) -> str:
        if option in sensitive_options or (
            is_sensitive_value is not None and is_sensitive_value(value)
        ):
            return "<value>"  # Never put a sensitive value into the warning text.
        return value

    warnings = []
    for index, token in enumerate(argv):
        if not token.startswith("-") or token.startswith("--") or token == "-":
            continue  # Ordinary values and correct long options need no warning.
        following = argv[index + 1] if index + 1 < len(argv) else None
        if following is None or following.startswith("-"):
            continue  # This hint needs a following value that parsing left over.
        intended_long = f"-{token}"
        if intended_long in long_options:
            value = display(intended_long, following)
            warnings.append(
                f'Suspicious CLI option "{token} {value}" was parsed as a '
                "short option with an attached value, leaving the next value "
                f'as a separate argument. Did you mean "{intended_long} {value}"?'
            )
            continue
        for short, canonical in short_options.items():
            if not token.startswith(short) or token == short:
                continue  # This option was not attached to an extra value.
            attached = token[len(short) :]
            if len(attached) > 2:
                break  # Longer attached values are usually deliberate.
            combined = f"{attached} {following}"
            value = display(short, combined)
            if short in sensitive_options or (
                is_sensitive_value is not None and is_sensitive_value(combined)
            ):
                warnings.append(
                    f'Suspicious CLI option "{short}" has an attached '
                    "value followed by another value token. Did you mean to "
                    f'quote the {canonical} value, for example "{short} {value}"?'
                )
            else:
                warnings.append(
                    f'Suspicious CLI option "{token} {following}" looks like '
                    f"a split value for {canonical}. Did you mean "
                    f'"{short} {value}"?'
                )
            break
    return warnings
