# Data

`template-rj-448.bin`: default Ruijie extension body that follows the encoded
23-byte IPv4 header in the classic (MentoHUST style) format. 448 bytes,
sha256 `efbd568cb78d250112beb27642949065a7361c3c9fd372f1d25086fe3adf828b`.
From the campus-auth-research spec pack (`data/ruijie/template-rj-448.bin`,
doc 18.3); offsets of the fields mentorust fills in are in `../classic.rs`.

`template-rj-v4-402.bin`: the 402 bytes that follow the 57-byte head in the
V4 extended format MentoHUST GS switches to on non-Ruijie switches (VA
0x423530), sha256
`2d66a00a1eb18173d6fd75cf07d2960c5f17b265d65a1b2218e09a4a5065b5c2`. Same spec
pack (`data/ruijie/template-rj-v4-402.bin`, doc 18.7); offsets in `../v4.rs`.
