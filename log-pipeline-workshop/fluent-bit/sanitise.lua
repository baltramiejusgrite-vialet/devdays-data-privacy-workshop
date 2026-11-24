-- Regex fast path for the known Lithuanian log format.
-- Emits only approved operational metadata plus the message with every sensitive
-- key=value pair redacted. Every other field of the input record is dropped.

local SENSITIVE = {
    darbuotojas = "name",
    asmens_kodas = "national_id",
    telefonas = "phone",
    adresas = "address",
    el_pastas = "email",
    atlyginimas = "financial",
}

local function redact_pairs(message, separator_pattern)
    -- A key must be immediately followed by its separator, so "Anketa: darbuotojas=..." is
    -- never read as key "Anketa" with "darbuotojas=..." as its value.
    return (string.gsub(message, "([%w_]+)(" .. separator_pattern .. ")([^;]*)", function(key, sep, value)
        local kind = SENSITIVE[key]
        if kind then
            return key .. sep .. "[REDACTED:" .. kind .. "]"
        end
        return nil
    end))
end

local function redact_message(message)
    local clean = redact_pairs(message, "=%s*")
    clean = redact_pairs(clean, ":%s*")
    return clean
end

local function plain(value)
    local kind = type(value)
    if kind == "number" then
        return value
    end
    if kind == "string" and string.match(value, "^[%w_.-]+$") and #value <= 64 then
        return value
    end
    return nil
end

function regex_path(tag, timestamp, record)
    local clean = {
        processing_path = "regex",
        service = plain(record["service"]),
        level = plain(record["level"]),
        event = plain(record["event"]),
        sequence = plain(record["sequence"]),
        message = redact_message(record["message"] or ""),
    }
    return 1, timestamp, clean
end
