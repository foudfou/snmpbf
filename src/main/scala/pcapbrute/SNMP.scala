package pcapbrute
/* Brute-forcing SNMP pcap —
 https://www.0x0ff.info/2013/snmpv3-authentification/
*/

import java.security._


object ByteUtils {
  // http://blog.tmyymmt.net/en/?p=71
  def hexToBytes(hex: String): Array[Byte] = {
    hex.replaceAll("[^0-9A-Fa-f]", "").sliding(2, 2).toArray.map(Integer.parseInt(_, 16).toByte)
  }

  def bytesToHex(bytes: Array[Byte], sep: Option[String] = None): String = {
    sep match {
      case None => bytes.map("%02x".format(_)).mkString
      case _ => bytes.map("%02x".format(_)).mkString(sep.get)
    }
  }

  def resetBytes(bytes: Array[Byte], from: Int, until: Int): Array[Byte] =
    (0 until bytes.length map { i =>
      if (from <= i && i < until)
        0.toByte
      else
        bytes(i)
    }).toArray

  // http://www.zapadlo.de/2013/xor-two-byte-arrays-in-scala/
  def xor(a: Array[Byte], b: Array[Byte]): Array[Byte] = {
    require(a.length == b.length, "Byte arrays have to have the same length")
    (a.toList zip b.toList).map(e => (e._1 ^ e._2).toByte).toArray
  }
}


class MD5(input: Array[Byte]) {
  def this(input: String) = this(input.getBytes("UTF-8"))

  val md5 = java.security.MessageDigest.getInstance("MD5")
  val bytes = {
    md5.update(input, 0, input.length)
    md5.digest()
  }

  override def toString = {
    new java.math.BigInteger(1, bytes).toString(16)
  }
}


object SNMP {
  import ByteUtils._

  // See rfc2574 A.2.2.
  def passwordToKeyMd5(password: String, engineID: String): MD5 = {
    val OneMega = 1048576
    val pwdStream = { password * (OneMega / password.length) +
      password.take(OneMega % password.length) }
    val md5pwd = new MD5(pwdStream)
    val localized = md5pwd.bytes ++ hexToBytes(engineID) ++ md5pwd.bytes
    new MD5(localized)
  }

  /* No asn1 decoding here: get values from another tool like wireshark. */
  def msgAuthenticationParameters(password: String, engineID: String,
    wholeMsg: String, msgAuthParamIndex: Int) = {
    require(msgAuthParamIndex % 2 == 0, "msgAuthParamIndex must be even")

    val wholeBytes = hexToBytes(wholeMsg)
    val paramByteIdx = msgAuthParamIndex / 2
    val wholeInitial = resetBytes(wholeBytes, paramByteIdx, paramByteIdx + 12)
    val authKey = passwordToKeyMd5(password, engineID)
    val authKeyExt = authKey.bytes ++ Array.fill(48)(0.toByte)
    val k1 = xor(authKeyExt, Array.fill(64)(0x36.toByte))
    val k2 = xor(authKeyExt, Array.fill(64)(0x5c.toByte))
    val m1 = new MD5(k1 ++ wholeInitial)
    val m2 = new MD5(k2 ++ m1.bytes)
    m2.bytes take 12
  }

  def main(args: Array[String]) {
    // val bis = new BufferedInputStream(new FileInputStream(fileName))

    // val chunkSize = 128 * 1024
    // val iterator = Source.fromFile(path).getLines.grouped(chunkSize)
    // iterator.foreach { lines =>
    //   lines.par.foreach { line => process(line) }
    // }
  }
}
