#include "key.hpp"

Key::Key(CK_OBJECT_HANDLE handle, const std::string& alias)
    : m_handle(handle), m_alias(alias)
{
}
