package snmpbf

import org.scalatest.FunSuite


class SNMPSuite extends FunSuite {
  import ByteUtils._
  import SNMP._

  val msgHex = "3081800201033011020420dd06a70203" +
  "00ffe30401050201030431302f041180001f8880e9bd0c1d12667a5100000000" +
  "020105020120040475736572040cb92621f4a93d1bf9738cd5bd040030350411" +
  "80001f8880e9bd0c1d12667a51000000000400a11e02046b4c5ac20201000201" +
  "003010300e060a2b06010201041e0105010500"

  val msgStr = "48 -127 -128 2 1 3 48 17 2 4 32 -35 6 -89 2 3" +
  " 0 -1 -29 4 1 5 2 1 3 4 49 48 47 4 17 -128" +
  " 0 31 -120 -128 -23 -67 12 29 18 102 122 81 0 0 0 0" +
  " 2 1 5 2 1 32 4 4 117 115 101 114 4 12 -71 38" +
  " 33 -12 -87 61 27 -7 115 -116 -43 -67 4 0 48 53 4 17" +
  " -128 0 31 -120 -128 -23 -67 12 29 18 102 122 81 0 0 0" +
  " 0 4 0 -95 30 2 4 107 76 90 -62 2 1 0 2 1" +
  " 0 48 16 48 14 6 10 43 6 1 2 1 4 30 1 5" +
  " 1 5 0"

  val msgRaw = Array[Byte](48, -127, -128, 2, 1, 3, 48, 17, 2, 4, 32, -35,
    6, -89, 2, 3, 0, -1, -29, 4, 1, 5, 2, 1, 3, 4, 49, 48, 47, 4, 17, -128, 0,
    31, -120, -128, -23, -67, 12, 29, 18, 102, 122, 81, 0, 0, 0, 0, 2, 1, 5, 2,
    1, 32, 4, 4, 117, 115, 101, 114, 4, 12, -71, 38, 33, -12, -87, 61, 27, -7,
    115, -116, -43, -67, 4, 0, 48, 53, 4, 17, -128, 0,
    31, -120, -128, -23, -67, 12, 29, 18, 102, 122, 81, 0, 0, 0, 0, 4, 0, -95,
    30, 2, 4, 107, 76, 90, -62, 2, 1, 0, 2, 1, 0, 48, 16, 48, 14, 6, 10, 43, 6,
    1, 2, 1, 4, 30, 1, 5, 1, 5,0)

  test("hexToBytes") {
    val msgx = hexToBytes(msgHex)
    assert(msgx.mkString(" ") == msgStr)
  }

  test("bytesToHex") {
    val msgs = bytesToHex(msgRaw)
    assert(msgs == msgHex)
  }

  test("xor") {
    // 21f1e9d9b30ceaeb84f2812beee685d5
    val b1 = Array[Byte](33, -15, -23, -39, -77, 12, -22, -21, -124, -14, -127,
      43, -18, -26, -123, -43)
    val b2 = Array.fill(16)(0x36.toByte)
    // 17c7dfef853adcddb2c4b71dd8d0b3e3
    val expect = Array[Byte](23, -57, -33, -17, -123,
      58, -36, -35, -78, -60, -73, 29, -40, -48, -77, -29)
    assert(xor(b1, b2).sameElements(expect))
  }

  test("md5") {
    val expectStr = "9695da4dd567a19f9b92065f240c6725"
    val expectRaw = Array(-106, -107, -38, 77, -43, 103, -95, -97, -101, -110,
      6, 95, 36, 12, 103, 37)

    val fromString = new MD5("secr3t")
    assert(fromString.bytes.sameElements(expectRaw))

    val fromBytes = new MD5(Array[Byte](115, 101, 99, 114, 51, 116))
    assert(fromBytes.bytes.sameElements(expectRaw))
  }

  test("passwordToKeyMd5") {
    val md5a = SNMP.passwordToKeyMd5("user", "80001f888062dc7f4c15465c5100000000")
    // "21f1e9d9b30ceaeb84f2812beee685d5"
    val expect1 = Array[Byte](33, -15, -23, -39, -77,
      12, -22, -21, -124, -14, -127, 43, -18, -26, -123, -43)
    assert(md5a.bytes.sameElements(expect1))

    val md5b = SNMP.passwordToKeyMd5("maplesyrup", "000000000000000000000002")
    // "526f5eed9fcce26f8964c2930787d82b"
    val expect2 = Array[Byte](82, 111, 94, -19, -97, -52, -30, 111, -119,
      100, -62, -109, 7, -121, -40, 43)
    assert(md5b.bytes.sameElements(expect2))
  }

  test("msgAuthenticationParameters") {
    // Decoded from wireshark.
    val whole = "30818002010330110204580b8cc70203" +
    "00ffe30401050201030431302f041180" +
    "001f888062dc7f4c15465c5100000000" +
    "02010302017c040475736572040c9b1b" +
    "71e33603a30c125f095d040030350411" +
    "80001f888062dc7f4c15465c51000000" +
    "000400a11e0204334304ff0201000201" +
    "003010300e060a2b06010201041e0105" +
    "010500"
    val engine = "80001f888062dc7f4c15465c5100000000"
    val param = "9b1b71e33603a30c125f095d"
    val paramBytes = Array[Byte](-101, 27, 113, -29, 54, 3, -93, 12, 18, 95, 9, 93)
    val paramIdx = whole indexOf param

    assert(msgAuthenticationParameters("user", engine, whole, paramIdx)
      .sameElements(paramBytes))
  }
}
