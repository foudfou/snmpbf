package snmpbf
/* Brute-forcing SNMP pcap —
 https://www.0x0ff.info/2013/snmpv3-authentification/
*/

import java.security._
import java.nio.charset.CodingErrorAction
import scala.io.{Codec, Source}


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


case class MD5(input: Stream[Byte]) {
  def this(input: Array[Byte]) = this(input.toStream)
  def this(input: String) = this(input.getBytes("UTF-8").toStream)

  val md5 = java.security.MessageDigest.getInstance("MD5")
  val bytes = {
    input.foreach(md5.update(_))
    md5.digest()
  }

  override def toString = {
    new java.math.BigInteger(1, bytes).toString(16)
  }
}


object SNMP {
  import ByteUtils._

  // See RFC2574 A.2.2.
  def passwordToKeyMd5(password: String, engineID: String): MD5 = {
    val OneMega = 1048576
    val pwdStream = Stream.continually(password).flatten.map(_.toByte)
      .take(OneMega)
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
}

object Brute extends App {
  import SNMP._
  import ByteUtils._

  val Usage = StringContext.treatEscapes("""usage: pcapbrute WHOLE ENGINE_ID AUTH_PARAM PASSWORD_DICT
    |
    |\tWHOLE ENGINE_ID AUTH_PARAM are hex strings.""".stripMargin)

  if (args.length == 0 || args(0) == "-h" || args(0) == "--help") {
    println(Usage)
    System.exit(0)
  }

  // input as hex strings
  val Whole = args(0)
  val EngineID = args(1)
  val Param = args(2)
  val paramIdx = Whole indexOf Param

  implicit val codec = Codec("UTF-8")
  codec.onMalformedInput(CodingErrorAction.REPLACE)
  codec.onUnmappableCharacter(CodingErrorAction.REPLACE)

  // Can't .par directly an Iterator[String], so convert to a Vector.par, not a
  // List.par which would double memory usage.
  // http://stackoverflow.com/a/13843530/421846
  Source.fromFile(args(3))
    .getLines.toIndexedSeq.par.map { password =>
      val param = msgAuthenticationParameters(password, EngineID, Whole, paramIdx)
      if (Param == bytesToHex(param))
        println(s"MATCH: $password")
  }

}
