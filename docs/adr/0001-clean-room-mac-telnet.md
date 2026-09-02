# 1. Clean-room MAC-Telnet, no GPL porting

The canonical MAC-Telnet client (`haakonnessjoen/MAC-Telnet`) is GPL-2.0, so
copying or line-by-line porting its code would force Tikl to be GPL. We
implement MAC-Telnet clean-room — using that project only as a behavioural
reference for the wire protocol — so Tikl can stay MIT, consistent with the
MIT curve code it already builds on.
