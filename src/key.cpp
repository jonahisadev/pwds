#include "key.hpp"

Key::Key(CK_OBJECT_HANDLE handle, KeyType type, const std::string& alias)
    : m_handle(handle), m_type(type), m_alias(alias)
{
}
