# The Java original source code was taken form http://www.milci.com/eappsjira
# Original Java source is included in comments followed by corresponding Ruby code.
# As original Java source is not documented then Ruby source code was done
# as similar as possible to Java code to avoid differences in functionality.
# 
# http://code.google.com/p/jebusinessauth/source/browse/trunk/src/com/milci/ebusinesssuite/eBusinessSuiteSecurity.java
# 

require "digest/sha1"

module OracleEbsAuthentication

  # public class eBusinessSuiteSecurity {
  class Security
    
    # public eBusinessSuiteSecurity() {
    # }
    def initialize
    end

    # static String control(String s1, int i1, String s2) {
    #   return newControl(s1, s2, i1, 0);
    # }
    def control(s1, i1, s2)
      return new_control(s1, s2, i1, 0)
    end

    #private static int[] a(byte abyte0[], int i1) {
    def a(abyte0, i1)
    #  int ai[] = new int[16];
      ai = [nil]*16
    #  int ai1[] = new int[5];
      ai1 = [nil]*5
    #  u(ai1, null);
      u(ai1, nil)
    #  int l1 = ai.length;
      l1 = ai.length
    #  int k1 = 0;
      k1 = 0
    #  int j2 = 0;
      j2 = 0
    #  int j1;
    #  for (j1 = 0; j1 < (i1 & -4); j1 += 4) {
      j1 = 0
      while j1 < (i1 & -4)
    #    ai[k1] = abyte0[j2] | abyte0[j2 + 1] << 8 | abyte0[j2 + 2] << 16 |
    #        abyte0[j2 + 3] << 24;
        ai[k1] = (abyte0[j2] | abyte0[j2 + 1] << 8 | abyte0[j2 + 2] << 16 |
            abyte0[j2 + 3] << 24) & 0xffffffff
    #    if (++k1 == l1) {
    #      u(ai1, ai);
    #      k1 = 0;
    #    }
        k1 +=1
        if (k1 == l1)
          u(ai1, ai)
          k1 = 0
        end
    #    j2 += 4;
        j2 += 4
    #  }
        j1 += 4
      end
    #
    #  j1 = i1 - j1;
      j1 = i1 - j1
    #  if (j1 == 1) {
    #    ai[k1] = abyte0[j2] & 0xff | 0x8000;
    #  }
      if (j1 == 1)
        ai[k1] = abyte0[j2] & 0xff | 0x8000
    #  else
    #  if (j1 == 2) {
    #    ai[k1] = abyte0[j2] | abyte0[j2 + 1] << 8 | 0x800000;
    #  }
      elsif (j1 == 2)
        ai[k1] = (abyte0[j2] | abyte0[j2 + 1] << 8 | 0x800000) & 0xffffffff
    #  else
    #  if (j1 == 3) {
    #    ai[k1] = abyte0[j2] | abyte0[j2 + 1] << 8 | abyte0[j2 + 2] << 16 |
    #        0x80000000;
    #  }
      elsif (j1 == 3)
        ai[k1] = (abyte0[j2] | abyte0[j2 + 1] << 8 | abyte0[j2 + 2] << 16 | 0x80000000) & 0xffffffff
    #  else {
    #    ai[k1] = 128;
    #  }
      else
        ai[k1] = 128
      end
    #  if (++k1 >= l1 - 2) {
    #    while (k1 < l1) {
    #      ai[k1++] = 0;
    #    }
    #    u(ai1, ai);
    #    k1 = 0;
    #  }
      k1 += 1
      if (k1 >= l1 - 2)
        while (k1 < l1)
          ai[k1] = 0
          k1 += 1
        end
        u(ai1,ai)
        k1 = 0
      end
    #  while (k1 < l1 - 2) {
    #    ai[k1++] = 0;
    #  }
      while (k1 < l1 - 2)
        ai[k1] = 0
        k1 += 1
      end
    #  int i2 = i1;
      i2 = i1
    #  ai[k1++] = i2 >> 29 & 7;
      ai[k1] = i2 >> 29 & 7
      k1 += 1
    #  ai[k1] = i2 << 3;
      ai[k1] = (i2 << 3) & 0xffffffff
    #  u(ai1, ai);
      u(ai1, ai)
    #  return ai1;
      return ai1
    #}
    end


    # static String newCheck(String s1, String s2, boolean flag) {
    def new_check(s1, s2, flag)
    #   if (s1 == null || s2 == null ||
    #       s2.length() >= "ZG_ENCRYPT_FAILED_".length() &&
    #       s2.substring(0,
    #                    "ZG_ENCRYPT_FAILED_".length()).equals("ZG_ENCRYPT_FAILED_")) {
    #     return null;
    #   }
      if (s1 == nil || s2 == nil ||
          s2.length >= "ZG_ENCRYPT_FAILED_".length &&
          s2[0, "ZG_ENCRYPT_FAILED_".length] == "ZG_ENCRYPT_FAILED_")
        return nil
      end
    #   byte abyte0[];
    #   try {
    #     abyte0 = s1.getBytes("UTF8");
    #   }
    #   catch (UnsupportedEncodingException _ex) {
    #     return null;
    #   }
      abyte0 = s1.dup
    #   int l2 = abyte0.length;
      l2 = abyte0.length
    #   int i3 = s2.length();
      i3 = s2.length
    #   int i1 = 1;
      i1 = 1
    #   byte byte0 = 2;
      byte0 = 2
    #   int j1 = i3 - 2 - i1 * 2;
      j1 = i3 - 2 - i1 * 2
    #   if (j1 <= 0) {
    #     return null;
    #   }
      if (j1 <= 0)
        return nil
      end
    #   int k1 = (j1 / 16) * 8;
      k1 = (j1 / 16) * 8
    #   if (k1 <= 0) {
    #     return null;
    #   }
      if (k1 <= 0)
        return nil
      end
    #   int l1 = (j1 % 16) / 2;
      l1 = (j1 % 16) / 2
    #   int i2 = l1 + i1;
      i2 = l1 + i1
    #   int j2 = k1 - 1 - byte0;
      j2 = k1 - 1 - byte0
    #   if (j2 <= 0) {
    #     return null;
    #   }
      if (j2 <= 0)
        return nil
      end
    #   if (!s2.substring(0, 2).equals("ZG")) {
    #     return null;
    #   }
      if (not s2[0, 2] == "ZG")
        return nil
      end
    #   String s3 = s2.substring(2);
      s3 = s2[2..-1]
    #   byte abyte1[] = p(s3);
      abyte1 = p(s3)
    #   byte abyte2[] = new byte[abyte1.length - i2];
      abyte2 = "\0"*(abyte1.length - i2)
    #   byte abyte3[] = new byte[i2];
      abyte3 = "\0"*i2
    #   System.arraycopy(abyte1, 0, abyte2, 0, abyte1.length - i2);
      abyte2[0, abyte1.length - i2] = abyte1[0, abyte1.length - i2]
    #   System.arraycopy(abyte1, abyte1.length - i2, abyte3, 0, i2);
      abyte3[0, i2] = abyte1[abyte1.length - i2, i2]
    #   byte abyte4[] = new byte[i2 + l2];
      abyte4 = "\0"*(i2 + l2)
    #   System.arraycopy(abyte3, 0, abyte4, 0, i2);
      abyte4[0, i2] = abyte3[0, i2]
    #   System.arraycopy(abyte0, 0, abyte4, i2, l2);
      abyte4[i2, l2] = abyte0[0, l2]
    #   byte abyte5[] = v(null, abyte4, abyte2);
      # puts "<br/>DEBUG new_check: abyte4=#{abyte4.inspect} abyte2=#{abyte2.unpack("H*")[0]}"
      abyte5 = v(nil, abyte4, abyte2)
    #   if (abyte5 == null) {
    #     return null;
    #   }
      if (abyte5 == nil)
        # puts "<br/>DEBUG new_check: :nil6"
        return nil
      end
    #   int j3 = abyte5.length;
      j3 = abyte5.length
    #   for (int k2 = byte0; k2 < abyte5.length; k2++) {
    #     if (abyte5[k2] != 0) {
    #       continue;
    #     }
    #     j3 = k2;
    #     break;
    #   }
      for k2 in byte0...abyte5.length
        if (abyte5[k2] != 0)
          next
        end
        j3 = k2
        break
      end
    # 
    #   byte abyte6[] = new byte[j3 - byte0];
      abyte6 = "\0"*(j3 - byte0)
    #   System.arraycopy(abyte5, byte0, abyte6, 0, j3 - byte0);
      abyte6[0, j3 - byte0] = abyte5[byte0, j3 - byte0]
    #   String s4;
    #   try {
    #     s4 = new String(abyte6, "UTF8");
    #   }
    #   catch (UnsupportedEncodingException _ex) {
    #     return null;
    #   }
      s4 = abyte6
    #   if (s4 != null && flag) {
    #     return w(s4, 0, flag);
    #   }
      if (s4 != nil && flag)
        return w(s4, 0, flag)
    #   else {
    #     return s4;
    #   }
      else
        return s4
      end
    # }
    end

    # private static void c(int ai[]) {
    #   ai[4] = j(ai[0], 5) + s(ai[1], ai[2], ai[3]) + ai[4] + ai[5] + 0x8f1bbcdc;
    #   ai[2] = j(ai[1], 30);
    # }
    def c(ai)
      ai[4] = j(ai[0], 5) + s(ai[1], ai[2], ai[3]) + ai[4] + ai[5] + 0x8f1bbcdc
      ai[2] = j(ai[1], 30)
    end

    # private static void d(byte abyte0[], int ai[]) {
    #   int ai1[] = new int[2];
    #   t(abyte0, ai1);
    #   F(ai1, ai);
    #   x(ai1, abyte0);
    # }
    def d(abyte0, ai)
      ai1 = [nil]*2
      t(abyte0, ai1)
      # puts "<br/>DEBUG d: after t abyte0=#{abyte0.unpack("H*")[0]}"
      # puts "<br/>DEBUG d: after t ai1=#{ai1.join(",")}"
      f_(ai1, ai)
      # puts "<br/>DEBUG d: after F ai1=#{ai1.join(",")}"
      # puts "<br/>DEBUG d: after F ai=#{ai.join(",")}"
      x(ai1, abyte0)
      # puts "<br/>DEBUG d: after x ai1=#{ai1.join(",")}"
      # puts "<br/>DEBUG d: after x abyte0=#{abyte0.unpack("H*")[0]}"
    end

    # private static byte[] e(int ai[]) {
    #   byte abyte0[] = new byte[4];
    #   byte abyte1[] = null;
    #   if (ai != null) {
    #     abyte1 = new byte[ai.length];
    #     for (int i1 = 0; i1 < ai.length; i1++) {
    #       abyte0[3] = (byte) (ai[i1] & 0xff);
    #       abyte0[2] = (byte) ( (ai[i1] & 0xff00) >> 8);
    #       abyte0[1] = (byte) ( (ai[i1] & 0xff0000) >> 16);
    #       abyte0[0] = (byte) ( (ai[i1] & 0xff000000) >> 24);
    #       abyte1[i1] = (byte) (abyte0[0] ^ abyte0[1] ^ abyte0[2] ^ abyte0[3]);
    #     }
    # 
    #   }
    #   return abyte1;
    # }
    def e(ai)
      abyte0 = "\0"*4
      abyte1 = nil
      if (ai != nil)
        abyte1 = "\0"*(ai.length)
        for i1 in 0...ai.length
          abyte0[3] = (ai[i1] & 0xff)
          abyte0[2] = ( (ai[i1] & 0xff00) >> 8)
          abyte0[1] = ( (ai[i1] & 0xff0000) >> 16)
          abyte0[0] = ( (ai[i1] & 0xff000000) >> 24)
          abyte1[i1] = (abyte0[0] ^ abyte0[1] ^ abyte0[2] ^ abyte0[3])
        end
      end
      return abyte1
    end

    # private static byte f(int i1) {
    #   byte byte0 = 0;
    #   int j1 = (char) i1 & 0x40;
    #   if (j1 >= 1) {
    #     byte0 = (byte) ( (char) i1 - 55);
    #   }
    #   else {
    #     byte0 = (byte) ( (char) i1 & 0xf);
    #   }
    #   return byte0;
    # }
    def f(i1)
      byte0 = 0
      j1 = i1 & 0x40
      if (j1 >= 1)
        byte0 = i1 - 55
      else
        byte0 = i1 & 0xf
      end
      return byte0
    end

    # private static byte[] g(byte abyte0[], byte abyte1[]) {
    def g(abyte0, abyte1)
    #   if (abyte0.length < 32) {
    #     return null;
    #   }
      if (abyte0.length < 32)
        # puts "<br/>DEBUG g: nil1"
        return nil
      end
    #   if (abyte1.length % 8 != 0) {
    #     return null;
    #   }
      if (abyte1.length % 8 != 0)
        # puts "<br/>DEBUG g: nil2"
        return nil
      end
    #   int i1 = abyte1.length / 8;
      i1 = abyte1.length / 8
    #   byte abyte3[] = new byte[8];
      abyte3 = "\0"*8
    #   byte abyte4[] = new byte[8];
      abyte4 = "\0"*8
    #   byte abyte5[] = new byte[8];
      abyte5 = "\0"*8
    #   byte abyte2[] = new byte[8];
      abyte2 = "\0"*8
    #   System.arraycopy(abyte0, 0, abyte3, 0, 8);
      abyte3[0,8] = abyte0[0, 8]
    #   System.arraycopy(abyte0, 8, abyte4, 0, 8);
      abyte4[0,8] = abyte0[8, 8]
    #   System.arraycopy(abyte0, 16, abyte5, 0, 8);
      abyte5[0,8] = abyte0[16, 8]
    #   System.arraycopy(abyte0, 24, abyte2, 0, 8);
      abyte2[0,8] = abyte0[24, 8]
    #   int ai[] = l(abyte3, false);
      ai = l(abyte3, false)
    #   int ai1[] = l(abyte4, true);
      ai1 = l(abyte4, true)
    #   int ai2[] = l(abyte5, false);
      ai2 = l(abyte5, false)
    #   byte abyte6[] = new byte[abyte1.length];
      abyte6 = "\0"*(abyte1.length)
    #   int j1 = 0;
      j1 = 0
    #   for (int k1 = 0; j1 < i1; k1 += 8) {
      k1 = 0
      while (j1 < i1)
    #     q(abyte1, k1, abyte6, k1, ai, ai1, ai2, abyte2, false);
        q(abyte1, k1, abyte6, k1, ai, ai1, ai2, abyte2, false)
        # puts "<br/>DEBUG g: after q() abyte6=#{abyte6.unpack("H*")[0]}"
    #     j1++;
        j1 += 1
    #   }
        k1 += 8
      end
    # 
    #   byte byte0 = abyte6[abyte1.length - 1];
      byte0 = abyte6[abyte1.length - 1]
      # puts "<br/>DEBUG g: abyte1=#{abyte1.unpack("H*")[0]}"
      # puts "<br/>DEBUG g: abyte1.length=#{abyte1.length}"
      # puts "<br/>DEBUG g: abyte6=#{abyte6.unpack("H*")[0]}"
    #   if (byte0 < 1 || byte0 > 8) {
    #     return null;
    #   }
      if (byte0 < 1 || byte0 > 8)
        # puts "<br/>DEBUG g: nil3"
        # puts "<br/>DEBUG g: byte0=#{byte0}"
        return nil
      end
    #   for (int l1 = abyte1.length - byte0; l1 < abyte1.length; l1++) {
      for l1 in (abyte1.length-byte0)...abyte1.length
    #     if (abyte6[l1] != byte0) {
    #       return null;
    #     }
        if (abyte6[l1] != byte0)
          # puts "<br/>DEBUG g: nil4"
          return nil
        end
    #   }
      end
    # 
    #   byte abyte7[] = new byte[abyte1.length - byte0];
      abyte7 = "\0"*(abyte1.length - byte0)
    #   System.arraycopy(abyte6, 0, abyte7, 0, abyte1.length - byte0);
      abyte7[0, abyte1.length - byte0] = abyte6[0, abyte1.length - byte0]
    #   return abyte7;
      # puts "<br/>DEBUG g: abyte7=#{abyte7.unpack("H*")[0]}"
      return abyte7
    # }
    end

    # private static void h(int ai[]) {
    #   ai[4] = j(ai[0], 5) + o(ai[1], ai[2], ai[3]) + ai[4] + ai[5] + 0xca62c1d6;
    #   ai[2] = j(ai[1], 30);
    # }
    def h(ai)
      ai[4] = j(ai[0], 5) + o(ai[1], ai[2], ai[3]) + ai[4] + ai[5] + 0xca62c1d6
      ai[2] = j(ai[1], 30)
    end

    # private static byte[] i(byte abyte0[], byte abyte1[], byte abyte2[]) {
    #   return G(y(abyte0, abyte1), abyte2);
    # }
    def i(abyte0, abyte1, abyte2)
      return g_(y(abyte0, abyte1), abyte2)
    end

    # private static int j(int i1, int j1) {
    #   return i1 << j1 | i1 >>> 32 - j1;
    # }
    # TODO: check impact of >>> substitution with >>
    def j(i1, j1)
      return (i1 << j1 | i1 >> 32 - j1) & 0xffffffff
    end

    # private static byte[] k(byte abyte0[], byte abyte1[], int i1) {
    def k(abyte0, abyte1, i1)
    #   if (abyte0 == null || abyte1 == null) {
    #     return null;
    #   }
      if (abyte0 == nil || abyte1 == nil)
        return nil
    #   else {
    #     int ai[] = a(abyte0, abyte0.length);
    #     byte abyte2[] = e(ai);
    #     byte abyte3[] = new byte[258];
    #     B(abyte3, abyte2, null, 5);
    #     byte abyte4[] = new byte[i1];
    #     B(abyte3, abyte1, abyte4, i1);
    #     return abyte4;
    #   }
      else
        ai = a(abyte0, abyte0.length)
        abyte2 = e(ai)
        abyte3 = "\0"*258
        b_(abyte3, abyte2, nil, 5)
        abyte4 = "\0"*i1
        b_(abyte3, abyte1, abyte4, i1)
        return abyte4
      end
    # }
    end

    # private static int[] l(byte abyte0[], boolean flag) {
    def l(abyte0, flag)
    #   byte abyte1[] = new byte[56];
      abyte1 = "\0"*56
    #   byte abyte2[] = new byte[56];
      abyte2 = "\0"*56
    #   int ai[] = new int[32];
      ai = [nil]*32
    #   for (int j1 = 0; j1 < 56; j1++) {
    #     byte byte0 = V[j1];
    #     int l2 = byte0 & 7;
    #     abyte1[j1] = (byte) ( (abyte0[byte0 >>> 3] & bi[l2]) == 0 ? 0 : 1);
    #   }
    # TODO: check impact of >>> substitution with >>
      for j1 in 0...56
        byte0 = V[j1]
        l2 = byte0 & 7
        abyte1[j1] = ( (abyte0[byte0 >> 3] & Bi[l2]) == 0 ? 0 : 1)
      end
    # 
    #   for (int i1 = 0; i1 < 16; i1++) {
      for i1 in 0...16
    #     int i3;
    #     if (flag) {
    #       i3 = i1 << 1;
    #     }
        if (flag)
          i3 = i1 << 1
    #     else {
    #       i3 = 15 - i1 << 1;
    #     }
        else
          i3 = 15 - i1 << 1
        end
    #     int j3 = i3 + 1;
        j3 = i3 + 1
    #     ai[i3] = ai[j3] = 0;
        ai[i3] = ai[j3] = 0
    #     for (int k1 = 0; k1 < 28; k1++) {
        for k1 in 0...28
    #       int j2 = k1 + bb[i1];
          j2 = k1 + Bb[i1]
    #       if (j2 < 28) {
    #         abyte2[k1] = abyte1[j2];
    #       }
          if (j2 < 28)
            abyte2[k1] = abyte1[j2]
    #       else {
    #         abyte2[k1] = abyte1[j2 - 28];
    #       }
          else
            abyte2[k1] = abyte1[j2 - 28]
          end
    #     }
        end
    # 
    #     for (int l1 = 28; l1 < 56; l1++) {
        for l1 in 28...56
    #       int k2 = l1 + bb[i1];
          k2 = l1 + Bb[i1]
    #       if (k2 < 56) {
    #         abyte2[l1] = abyte1[k2];
    #       }
          if (k2 < 56)
            abyte2[l1] = abyte1[k2]
    #       else {
    #         abyte2[l1] = abyte1[k2 - 28];
    #       }
          else
            abyte2[l1] = abyte1[k2 - 28]
          end
    #     }
        end
    # 
    #     for (int i2 = 0; i2 < 24; i2++) {
        for i2 in 0...24
    #       if (abyte2[S[i2]] != 0) {
    #         ai[i3] |= W[i2];
    #       }
          if (abyte2[S[i2]] != 0)
            ai[i3] |= W[i2]
          end
    #       if (abyte2[S[i2 + 24]] != 0) {
    #         ai[j3] |= W[i2];
    #       }
          if (abyte2[S[i2 + 24]] != 0)
            ai[j3] |= W[i2]
          end
    #     }
        end
    # 
    #   }
      end
    # 
    #   return C(ai);
      return c_(ai)
    # }
    end

    # static String oldControl(String s1, String s2, int i1) {
    def old_control(s1, s2, i1)
    #   if (s1 == null || s2 == null) {
    #     return null;
    #   }
      if (s1 == nil || s2 == nil)
        return nil
      end
    #   byte abyte0[] = A(s1.toCharArray());
      abyte0 = a_(s1.dup)
    #   int j1 = s2.length();
      #j1 = s2.mb_chars.length
      j1 = s2.length
      
    #   if (j1 > i1 - 1) {
    #     j1 = i1 - 1;
    #   }
      if (j1 > i1 - 1)
        j1 = i1 - 1
      end
    #   Random random = new Random();
    # RSI: no need to create object here
    #   int k1 = i1 - j1 - 1;
      k1 = i1 - j1 - 1
    #   int ai[] = new int[k1];
      ai = [nil]*k1
    #   for (int l1 = 0; l1 < k1; l1++) {
    #     ai[l1] = random.nextInt();
    # 
    #   }
    # TODO: substitute Java random.nextInt() with ruby
      for l1 in 0..k1
        # simulation of random.nextInt()
        ai[l1] = rand(2**32)-2**31
      end
    #   byte abyte1[] = e(ai);
      abyte1 = e(ai)
    #   byte abyte2[] = A( (new String(s2 + '\0')).toCharArray());
      abyte2 = a_( (s2 + "\0") )
    #   byte abyte3[] = new byte[k1 + abyte2.length];
      abyte3 = "\0"*(k1 + abyte2.length)
    #   System.arraycopy(abyte2, 0, abyte3, 0, abyte2.length);
      abyte3[0, abyte2.length] = abyte2[0, abyte2.length]
    #   System.arraycopy(abyte1, 0, abyte3, abyte2.length, k1);
      abyte3[abyte2.length, k1] = abyte1[0, k1]
    #   byte abyte4[] = k(abyte0, abyte3, i1);
      abyte4 = k(abyte0, abyte3, i1)
    #   return z(abyte4);
      return z(abyte4)
    # }
    end

    # private static char[] m(byte abyte0[]) {
    def m(abyte0)
    #   char ac1[];
    #   label0: {
      while true
    #     if (abyte0 == null) {
    #       return null;
    #     }
        if (abyte0 == nil)
          return nil
        end
    #     char ac[] = new char[abyte0.length];
        ac = "\0"*(abyte0.length)
    #     int i1 = 0;
        i1 = 0
    #     boolean flag = false;
        flag = false
    #     boolean flag1 = false;
        flag1 = false
    #     ac1 = null;
        ac1 = nil
    #     try {
        begin
    #       for (int j1 = 0; j1 < abyte0.length; j1++) {
          break_value = for j1 in 0...abyte0.length do
    #         byte byte0 = abyte0[j1];
            byte0 = abyte0[j1]
    #         if ( (byte0 & 0x80) == 0) {
    #           ac[i1++] = (char) byte0;
    #           if ( (char) byte0 == 0) {
    #             break;
    #           }
    #           continue;
    #         }
            if ( (byte0 & 0x80) == 0)
              ac[i1] = byte0
              i1 += 1
              if ( byte0 == 0)
                break
              end
              next
            end
    #         if ( (byte0 & 0xe0) == 192) {
    #           char c1 = (char) ( (byte0 & 0x1f) << 6 & 0x7c0);
    #           byte0 = abyte0[++j1];
    #           if ( (byte0 & 0x80) == 128) {
    #             c1 |= byte0 & 0x3f;
    #             ac[i1++] = c1;
    #             continue;
    #           }
    #           break label0;
    #         }
            if ( (byte0 & 0xe0) == 192)
              c1 = ( (byte0 & 0x1f) << 6 & 0x7c0)
              j1 += 1
              byte0 = abyte0[j1]
              if ( (byte0 & 0x80) == 128)
                c1 |= byte0 & 0x3f
                ac[i1] = c1
                i1 += 1
                next
              end
              break :label0
            end
    #         if ( (byte0 & 0xf0) != 224) {
    #           continue;
    #         }
            if ( (byte0 & 0xf0) != 224)
              continue
            end
    #         char c2 = (char) ( (byte0 & 0xf) << 12 & 0xf000);
            c2 = ( (byte0 & 0xf) << 12 & 0xf000)
    #         byte0 = abyte0[++j1];
            j1 += 1
            byte0 = abyte0[j1]
    #         if ( (byte0 & 0x80) != 128) {
    #           break label0;
    #         }
            if ( (byte0 & 0x80) != 128)
              break :label0
            end
    #         c2 |= (byte0 & 0x3f) << 6 & 0xfc0;
            c2 |= (byte0 & 0x3f) << 6 & 0xfc0
    #         byte0 = abyte0[++j1];
            j1 += 1
            byte0 = abyte0[j1]
    #         if ( (byte0 & 0x80) != 128) {
    #           break label0;
    #         }
            if ( (byte0 & 0x80) != 128)
              break :label0
            end
    #         c2 |= byte0 & 0x3f;
            c2 |= byte0 & 0x3f
    #         ac[i1++] = c2;
            ac[i1] = c2
            i1 += 1
    #       }
          end
          # RSI: jump back to label0 if brake was called with :label0
          if break_value == :label0
            next
          end
    # 
    #       ac1 = new char[i1];
          ac1 = "\0"*i1
    #       System.arraycopy(ac, 0, ac1, 0, i1);
          ac1[0,i1] = ac[0,i1]
    #     }
    #     catch (ArrayIndexOutOfBoundsException _ex) {
    #       ac1 = null;
    #     }
        end
    # TODO: when this exception could happen?
    #   }
    #   return ac1;
    # }
    # RSI: if we are here then we should return value and escape endless loop
        return ac1
      end
    end


    # private static int n(int i1, int j1, int k1) {
    #   return i1 ^ j1 ^ k1;
    # }
    def n(i1, j1, k1)
      return i1 ^ j1 ^ k1
    end
    
    # private static int o(int i1, int j1, int k1) {
    #   return i1 ^ j1 ^ k1;
    # }
    def o(i1, j1, k1)
      return i1 ^ j1 ^ k1
    end

    # static String control(String s1, String s2, int i1) {
    #   return newControl(s1, s2, 0, i1);
    # }
    def control(s1, s2, i1)
      return new_control(s1, s2, 0, i1)
    end
    
    # private static byte[] p(String s1) {
    def p(s1)
    #   boolean flag = false;
      flag = false
    #   boolean flag1 = false;
      flag1 = false
    #   int i1 = 0;
      i1 = 0
    #   int j1 = 0;
      j1 = 0
    #   byte abyte0[] = null;
      abyte0 = nil
    #   if (s1 == null) {
    #     return null;
    #   }
      if (s1 == nil)
        return nil
      end
    #   int k1 = s1.length() / 2;
      k1 = s1.length / 2
    #   if (k1 > 0) {
      if (k1 > 0)
    #     abyte0 = new byte[k1];
        abyte0 = "\0"*k1
    #     for (; k1 > 0; k1--) {
        while (k1 > 0)
    #       char c1 = s1.charAt(i1++);
          #c1 = s1.chars[i1]
          c1 = s1[i1]
          i1 += 1
    #       char c2 = s1.charAt(i1++);
          #c2 = s1.chars[i1]
          c2 = s1[i1]
          i1 += 1
    #       abyte0[j1++] = (byte) (f(c1) << 4 | f(c2));
          abyte0[j1] = (f(c1) << 4 | f(c2)) & 0xffffffff
          j1 += 1
    #     }
          k1 -= 1
        end
    # 
    #   }
      end
    #   return abyte0;
      return abyte0
    # }
    end

    # private static void q(byte abyte0[], int i1, byte abyte1[], int j1, int ai[],
    #                       int ai1[], int ai2[], byte abyte2[],
    #                       boolean flag) {
    def q(abyte0, i1, abyte1, j1, ai,
          ai1, ai2, abyte2,
          flag)
    #   byte abyte3[] = new byte[8];
      abyte3 = "\0"*8
    #   System.arraycopy(abyte0, i1, abyte3, 0, 8);
      abyte3[0, 8] = abyte0[i1, 8]
    #   if (!flag) {
    #     d(abyte3, ai2);
    #     d(abyte3, ai1);
    #     d(abyte3, ai);
    #     D(abyte3, abyte2, abyte1, j1);
    #     System.arraycopy(abyte0, i1, abyte2, 0, 8);
    #     return;
    #   }
      if (!flag)
        # puts "<br/>DEBUG q: initial abyte3=#{abyte3.unpack("H*")[0]}"
        # puts "<br/>DEBUG q: initial ai2=#{ai2.join(',')}"
        # puts "<br/>DEBUG q: initial ai1=#{ai1.join(',')}"
        # puts "<br/>DEBUG q: initial ai=#{ai.join(',')}"
        d(abyte3, ai2)
        # puts "<br/>DEBUG q: abyte3=#{abyte3.unpack("H*")[0]}"
        d(abyte3, ai1)
        # puts "<br/>DEBUG q: abyte3=#{abyte3.unpack("H*")[0]}"
        d(abyte3, ai)
        # puts "<br/>DEBUG q: abyte3=#{abyte3.unpack("H*")[0]}"
        d_(abyte3, abyte2, abyte1, j1)
        # puts "<br/>DEBUG q: abyte3=#{abyte3.unpack("H*")[0]}"
        # puts "<br/>DEBUG q: abyte2=#{abyte2.unpack("H*")[0]}"
        # puts "<br/>DEBUG q: abyte1=#{abyte1.unpack("H*")[0]}"
        abyte2[0, 8] = abyte0[i1, 8]
        return
    #   else {
    #     D(abyte3, abyte2, abyte3, 0);
    #     d(abyte3, ai);
    #     d(abyte3, ai1);
    #     d(abyte3, ai2);
    #     System.arraycopy(abyte3, 0, abyte2, 0, 8);
    #     System.arraycopy(abyte3, 0, abyte1, j1, 8);
    #     return;
    #   }
      else
        d_(abyte3, abyte2, abyte3, 0);
        d(abyte3, ai);
        d(abyte3, ai1);
        d(abyte3, ai2);
        abyte2[0, 8] = abyte3[0, 8]
        abyte1[j1, 8] = abyte3[0, 8]
        return
      end
    # }
    end

    # private static int r(int i1, int j1, int k1) {
    #   return i1 & j1 | ~i1 & k1;
    # }
    def r(i1, j1, k1)
      return i1 & j1 | ~i1 & k1
    end

    # private static int s(int i1, int j1, int k1) {
    #   return i1 & j1 | i1 & k1 | j1 & k1;
    # }
    def s(i1, j1, k1)
      return i1 & j1 | i1 & k1 | j1 & k1
    end

    # static String hash(String s1) {
    def hash(s1)
    #   if (s1 == null) {
    #     return null;
    #   }
      if (s1 == nil)
        return nil
      end
    #   byte abyte0[];
    #   try {
    #     abyte0 = s1.getBytes("UTF8");
    #   }
    #   catch (UnsupportedEncodingException _ex) {
    #     return null;
    #   }
      abyte0 = s1.dup
    #   byte abyte1[] = y(null, abyte0);
      abyte1 = y(nil, abyte0)
    #   return z(abyte1);
      return z(abyte1)
    # }
    end

    # static String newControl(String s1, String s2, int i1, int j1) {
    def new_control(s1, s2, i1, j1)
    #   if (s1 == null || s2 == null) {
    #     return "ZG_ENCRYPT_FAILED_BADINPUT";
    #   }
      if (s1 == nil || s2 == nil)
        return "ZG_ENCRYPT_FAILED_BADINPUT"
      end
    #   int k1;
    #   if (i1 > 0) {
    #     k1 = i1;
    #   }
      if (i1 > 0)
        k1 = i1
    #   else
    #   if (j1 == 32) {
    #     k1 = 100;
    #   }
      elsif (j1 == 32)
        k1 = 100
    #   else
    #   if (j1 < 32 && j1 == s2.length()) {
    #     k1 = 100;
    #   }
      elsif (j1 < 32 && j1 == s2.length())
        k1 = 100
    #   else {
    #     byte abyte1[];
    #     try {
    #       abyte1 = s2.getBytes("UTF8");
    #     }
    #     catch (UnsupportedEncodingException _ex) {
    #       return "ZG_ENCRYPT_FAILED_MISC";
    #     }
    #     k1 = ( (abyte1.length + 10) / 8) * 16 + 4 + 14;
    #   }
      else
        abyte1 = s2.dup
        k1 = ( (abyte1.length + 10) / 8) * 16 + 4 + 14
      end
    #   int l1 = 1;
      l1 = 1
    #   byte byte0 = 2;
      byte0 = 2
    #   int i2 = k1 - 2 - l1 * 2;
      i2 = k1 - 2 - l1 * 2
    #   if (i2 <= 0) {
    #     return "ZG_ENCRYPT_FAILED_SMALLBUF";
    #   }
      if (i2 <= 0)
        return "ZG_ENCRYPT_FAILED_SMALLBUF"
      end
    #   int j2 = (i2 / 16) * 8;
      j2 = (i2 / 16) * 8
    #   if (j2 <= 0) {
    #     return "ZG_ENCRYPT_FAILED_SMALLBUF";
    #   }
      if (j2 <= 0)
        return "ZG_ENCRYPT_FAILED_SMALLBUF"
      end
    #   int k2 = (i2 % 16) / 2;
      k2 = (i2 % 16) / 2
    #   int l2 = k2 + l1;
      l2 = k2 + l1
    #   int i3 = j2 - 1 - byte0;
      i3 = j2 - 1 - byte0
    #   if (i3 <= 0) {
    #     return "ZG_ENCRYPT_FAILED_SMALLBUF";
    #   }
      if (i3 <= 0)
        return "ZG_ENCRYPT_FAILED_SMALLBUF"
      end
    #   byte abyte0[];
    #   byte abyte2[];
    #   try {
    #     abyte0 = s1.getBytes("UTF8");
    #     abyte2 = s2.getBytes("UTF8");
    #   }
    #   catch (UnsupportedEncodingException _ex) {
    #     return "ZG_ENCRYPT_FAILED_MISC";
    #   }
      abyte0 = s1.dup
      abyte2 = s2.dup
    #   int j3 = abyte0.length;
      j3 = abyte0.length
    #   int k3 = abyte2.length;
      k3 = abyte2.length
    #   if (k3 > i3) {
    #     return "ZG_ENCRYPT_FAILED_CHARSET_CLIP";
    #   }
      if (k3 > i3)
        return "ZG_ENCRYPT_FAILED_CHARSET_CLIP"
      end
    #   Random random = new Random();
    #   int ai[] = new int[l2];
      ai = [nil]*l2
    #   for (int l3 = 0; l3 < l2; l3++) {
    #     ai[l3] = random.nextInt();
    # 
    #   }
      for l3 in 0...l2
        ai[l3] = rand(2**32)-2**31
      end
    #   byte abyte3[] = e(ai);
      abyte3 = e(ai)
    #   ai = null;
      ai = nil
    #   byte byte1 = byte0;
      byte1 = byte0
    #   ai = new int[byte1];
      ai = [nil]*byte1
    #   for (int i4 = 0; i4 < byte1; i4++) {
    #     ai[i4] = random.nextInt();
    # 
    #   }
      for i4 in 0...byte1
        ai[i4] = rand(2**32)-2**31
      end
    #   byte abyte4[] = e(ai);
      abyte4 = e(ai)
    #   ai = null;
      ai = nil
    #   int j4 = i3 - k3;
      j4 = i3 - k3
    #   ai = new int[j4];
      ai = [nil]*j4
    #   for (int k4 = 0; k4 < j4; k4++) {
      for k4 in 0...j4
    #     if (k4 == 0) {
    #       ai[k4] = 0;
    #     }
        if (k4 == 0)
          ai[k4] = 0
    #     else {
    #       ai[k4] = random.nextInt();
    # 
    #     }
        else
          ai[k4] = rand(2**32)-2**31
        end
    #   }
      end
    #   byte abyte5[] = e(ai);
      abyte5 = e(ai)
    #   ai = null;
      ai = nil
    #   byte abyte6[] = new byte[byte1 + j4 + k3];
      abyte6 = "\0"*(byte1 + j4 + k3)
    #   System.arraycopy(abyte4, 0, abyte6, 0, byte1);
      abyte6[0, byte1] = abyte4[0, byte1]
    #   System.arraycopy(abyte2, 0, abyte6, byte1, k3);
      abyte6[byte1, k3] = abyte2[0, k3]
    #   System.arraycopy(abyte5, 0, abyte6, byte1 + k3, j4);
      abyte6[byte1+k3, j4] = abyte5[0, j4]
    #   byte abyte7[] = new byte[l2 + j3];
      abyte7 = "\0"*(l2 + j3)
    #   System.arraycopy(abyte3, 0, abyte7, 0, l2);
      abyte7[0, l2] = abyte3[0, l2]
    #   System.arraycopy(abyte0, 0, abyte7, l2, j3);
      abyte7[l2, j3] = abyte0[0, j3]
    #   byte abyte8[] = i(null, abyte7, abyte6);
      abyte8 = i(nil, abyte7, abyte6)
    #   if (abyte8 == null) {
    #     return "ZG_ENCRYPT_FAILED_MISC";
    #   }
      if (abyte8 == nil)
        return "ZG_ENCRYPT_FAILED_MISC"
    #   else {
    #     byte abyte9[] = new byte[abyte8.length + l2];
    #     System.arraycopy(abyte8, 0, abyte9, 0, abyte8.length);
    #     System.arraycopy(abyte3, 0, abyte9, abyte8.length, l2);
    #     String s3 = z(abyte9);
    #     return "ZG" + s3;
    #   }
      else
        abyte9 = "\0"*(abyte8.length + l2)
        abyte9[0, abyte8.length] = abyte8[0, abyte8.length]
        abyte9[abyte8.length, l2] = abyte3[0, l2]
        s3 = z(abyte9)
        return "ZG" + s3
      end
    # }
    end

    # private static void t(byte abyte0[], int ai[]) {
    def t(abyte0, ai)
    #   int i1 = 0;
      i1 = 0
    #   ai[0] = (abyte0[i1] & 0xff) << 24;
      ai[0] = ((abyte0[i1] & 0xff) << 24)  & 0xffffffff
    #   i1++;
      i1 += 1
    #   ai[0] |= (abyte0[i1] & 0xff) << 16;
      ai[0] |= ((abyte0[i1] & 0xff) << 16) & 0xffffffff
    #   i1++;
      i1 += 1
    #   ai[0] |= (abyte0[i1] & 0xff) << 8;
      ai[0] |= ((abyte0[i1] & 0xff) << 8) & 0xffffffff
    #   i1++;
      i1 += 1
    #   ai[0] |= abyte0[i1] & 0xff;
      ai[0] |= abyte0[i1] & 0xff
    #   i1++;
      i1 += 1
    #   ai[1] = (abyte0[i1] & 0xff) << 24;
      ai[1] = ((abyte0[i1] & 0xff) << 24) & 0xffffffff
    #   i1++;
      i1 += 1
    #   ai[1] |= (abyte0[i1] & 0xff) << 16;
      ai[1] |= ((abyte0[i1] & 0xff) << 16) & 0xffffffff
    #   i1++;
      i1 += 1
    #   ai[1] |= (abyte0[i1] & 0xff) << 8;
      ai[1] |= ((abyte0[i1] & 0xff) << 8) & 0xffffffff
    #   i1++;
      i1 += 1
    #   ai[1] |= abyte0[i1] & 0xff;
      ai[1] |= abyte0[i1] & 0xff
    # }
    end

    # private static int u(int ai[], int ai1[]) {
    def u(ai, ai1)
    #   boolean flag = false;
      flag = false
    #   boolean flag1 = false;
      flag1 = false
    #   int ai2[] = new int[80];
      ai2 = [nil]*80
    #   int l1 = 0;
      l1 = 0
    #   int ai3[] = new int[5];
      ai3 = [nil]*5
    #   int ai4[] = new int[6];
      ai4 = [nil]*6
    #   int ai5[] = new int[5];
      ai5 = [nil]*5
    #   ai3[0] = 0x67452301;
    #   ai3[1] = 0xefcdab89;
    #   ai3[2] = 0x98badcfe;
    #   ai3[3] = 0x10325476;
    #   ai3[4] = 0xc3d2e1f0;
      ai3[0] = 0x67452301
      ai3[1] = 0xefcdab89
      ai3[2] = 0x98badcfe
      ai3[3] = 0x10325476
      ai3[4] = 0xc3d2e1f0
    #   if (ai1 != null) {
      if (ai1 != nil)
    #     if (ai != null) {
    #       System.arraycopy(ai, 0, ai4, 0, 5);
    #     }
        if (ai != nil)
          ai4[0, 5] = ai[0, 5]
        end
    #     byte byte0 = 80;
        byte0 = 80
    #     int i1;
    #     for (i1 = 0; i1 < 16; i1++) {
    #       ai2[i1] = ai1[i1];
    # 
    #     }
        for i1 in 0...16
          ai2[i1] = ai1[i1]
        end
    #     for (; i1 < byte0; i1++) {
    #       ai2[i1] = ai2[i1 - 3] ^ ai2[i1 - 8] ^ ai2[i1 - 14] ^ ai2[i1 - 16];
    # 
    #     }
        while (i1 < byte0)
          ai2[i1] = ai2[i1 - 3] ^ ai2[i1 - 8] ^ ai2[i1 - 14] ^ ai2[i1 - 16]
          i1 += 1
        end
    #     for (int j1 = 0; j1 < 80; j1++) {
        for j1 in 0...80
    #       if (j1 != 0) {
    #         System.arraycopy(ai4, 0, ai5, 0, 5);
    #         ai4[0] = ai5[4];
    #         ai4[1] = ai5[0];
    #         ai4[2] = ai5[1];
    #         ai4[3] = ai5[2];
    #         ai4[4] = ai5[3];
    #       }
          if (j1 != 0)
            ai5[0, 5] = ai4[0, 5]
            ai4[0] = ai5[4];
            ai4[1] = ai5[0];
            ai4[2] = ai5[1];
            ai4[3] = ai5[2];
            ai4[4] = ai5[3];
          end
    #       ai4[5] = ai2[j1];
          ai4[5] = ai2[j1]
    #       if (j1 < 20) {
    #         H(ai4);
    #       }
          if (j1 < 20)
            h_(ai4)
    #       else
    #       if (j1 < 40) {
    #         I(ai4);
    #       }
          elsif (j1 < 40)
            i_(ai4)
    #       else
    #       if (j1 < 60) {
    #         c(ai4);
    #       }
          elsif (j1 < 60)
            c(ai4)
    #       else
    #       if (j1 < 80) {
    #         h(ai4);
    #       }
          elsif (j1 < 80)
            h(ai4)
          end
    #     }
        end
    # 
    #     ai3[0] = ai4[4];
    #     ai3[1] = ai4[0];
    #     ai3[2] = ai4[1];
    #     ai3[3] = ai4[2];
    #     ai3[4] = ai4[3];
        ai3[0] = ai4[4];
        ai3[1] = ai4[0];
        ai3[2] = ai4[1];
        ai3[3] = ai4[2];
        ai3[4] = ai4[3];
    #     for (int k1 = 0; k1 < byte0; k1++) {
    #       ai2[k1] = 0;
    # 
    #     }
        for k1 in 0...byte0
          ai2[k1] = 0
        end
    #   }
      end
    #   if (ai != null) {
    #     ai[0] = ai3[0];
    #     ai[1] = ai3[1];
    #     ai[2] = ai3[2];
    #     ai[3] = ai3[3];
    #     ai[4] = ai3[4];
    #   }
      if (ai != nil)
        ai[0] = ai3[0];
        ai[1] = ai3[1];
        ai[2] = ai3[2];
        ai[3] = ai3[3];
        ai[4] = ai3[4];
      end
    #   l1 = ai3[0] ^ ai3[1] ^ ai3[2] ^ ai3[3] ^ ai3[4];
      l1 = ai3[0] ^ ai3[1] ^ ai3[2] ^ ai3[3] ^ ai3[4]
    #   return l1;
      return l1
    # }
    end

    # private static byte[] v(byte abyte0[], byte abyte1[], byte abyte2[]) {
    #   return g(y(abyte0, abyte1), abyte2);
    # }
    def v(abyte0, abyte1, abyte2)
      return g(y(abyte0, abyte1), abyte2)
    end

    # private static String w(String s1, int i1, boolean flag) {
    def w(s1, i1, flag)
    #   if (s1 == null) {
    #     return "";
    #   }
      if (s1 == nil)
        return ""
      end
    #   int j1 = s1.length();
    # TODO: should String be converted to Ruby Unicode chars string? 
      j1 = s1.length
    #   int k1 = s1.indexOf('\0');
      k1 = s1.index("\0")
    #   if (k1 > -1) {
    #     j1 = k1;
    #   }
      if (k1 > -1)
        j1 = k1
      end
    #   int l1;
    #   if (j1 > i1 && i1 > 0) {
    #     l1 = i1;
    #   }
      if (j1 > i1 && i1 > 0)
        l1 = i1
    #   else {
    #     l1 = j1;
    #   }
      else
        l1 = j1
      end
    #   if (flag) {
    #     return new String(s1.substring(0, l1).toUpperCase(Locale.US));
    #   }
      if (flag)
        # TODO: should we do Unicode upcase?
        return s1[0, l1].upcase
    #   else {
    #     return new String(s1.substring(0, l1));
    #   }
      else
        return s1[0, l1]
      end
    # }
    end

    # private static void x(int ai[], byte abyte0[]) {
    def x(ai, abyte0)
    #   int i1 = 0;
      i1 = 0
    #   abyte0[i1] = (byte) (ai[0] >> 24 & 0xff);
      abyte0[i1] = (ai[0] >> 24 & 0xff)
    #   i1++;
      i1 += 1
    #   abyte0[i1] = (byte) (ai[0] >> 16 & 0xff);
      abyte0[i1] = (ai[0] >> 16 & 0xff)
    #   i1++;
      i1 += 1
    #   abyte0[i1] = (byte) (ai[0] >> 8 & 0xff);
      abyte0[i1] = (ai[0] >> 8 & 0xff)
    #   i1++;
      i1 += 1
    #   abyte0[i1] = (byte) (ai[0] & 0xff);
      abyte0[i1] = (ai[0] & 0xff)
    #   i1++;
      i1 += 1
    #   abyte0[i1] = (byte) (ai[1] >> 24 & 0xff);
      abyte0[i1] = (ai[1] >> 24 & 0xff)
    #   i1++;
      i1 += 1
    #   abyte0[i1] = (byte) (ai[1] >> 16 & 0xff);
      abyte0[i1] = (ai[1] >> 16 & 0xff)
    #   i1++;
      i1 += 1
    #   abyte0[i1] = (byte) (ai[1] >> 8 & 0xff);
      abyte0[i1] = (ai[1] >> 8 & 0xff)
    #   i1++;
      i1 += 1
    #   abyte0[i1] = (byte) (ai[1] & 0xff);
      abyte0[i1] = (ai[1] & 0xff)
    # }
    end
    
    # static String oldCheck(String s1, String s2, boolean flag) {
    def old_check(s1, s2, flag)
    #   byte abyte0[] = A(s1.toCharArray());
      abyte0 = a_(s1.dup)
    #   byte abyte1[] = p(s2);
      abyte1 = p(s2)
    #   byte abyte2[] = k(abyte0, abyte1, abyte1.length);
      abyte2 = k(abyte0, abyte1, abyte1.length)
    #   char ac[] = m(abyte2);
      ac = m(abyte2)
    #   if (ac != null) {
    #     String s3 = new String(ac);
    #     return w(s3, 0, flag);
    #   }
      if (ac != nil)
        s3 = ac.to_s
    #   else {
    #     return null;
    #   }
      else
        return nil
      end
    # }
    end

    # private static byte[] y(byte abyte0[], byte abyte1[]) {
    def y(abyte0, abyte1)
      # puts "<br/>DEBUG y: abyte0=#{abyte0.nil? ? "nil" : abyte0.unpack("H*")[0]}"
      # puts "<br/>DEBUG y: abyte1=#{abyte1.nil? ? "nil" : abyte1.unpack("H*")[0]}"
    #   byte abyte2[] = new byte[32];
      abyte2 = "\0"*32
    #   MessageDigest messagedigest;
    #   try {
    #     messagedigest = MessageDigest.getInstance("SHA");
    #   }
    #   catch (NoSuchAlgorithmException _ex) {
    #     return null;
    #   }
      messagedigest = Digest::SHA1.new
    #   messagedigest.reset();
      messagedigest.reset
    #   byte byte0 = 20;
      byte0 = 20
    #   if (abyte0 != null && abyte0.length > 0) {
    #     messagedigest.update(abyte0);
    #   }
      if (abyte0 != nil && abyte0.length > 0)
        messagedigest.update(abyte0)
      end
    #   if (abyte1 != null && abyte1.length > 0) {
    #     messagedigest.update(abyte1);
    #   }
      if (abyte1 != nil && abyte1.length > 0)
        messagedigest.update(abyte1)
      end
    #   messagedigest.update( (byte) 1);
      messagedigest.update(1.chr)
    #   byte abyte3[] = messagedigest.digest();
      abyte3 = messagedigest.digest
      # puts "<br/>DEBUG y: abyte3=#{abyte3.nil? ? "nil" : abyte3.unpack("H*")[0]}"
    #   System.arraycopy(abyte3, 0, abyte2, 0, byte0);
      abyte2[0, byte0] = abyte3[0, byte0]
    #   messagedigest.reset();
      messagedigest.reset()
    #   if (abyte0 != null && abyte0.length > 0) {
    #     messagedigest.update(abyte0);
    #   }
      if (abyte0 != nil && abyte0.length > 0)
        messagedigest.update(abyte0)
      end
    #   if (abyte1 != null && abyte1.length > 0) {
    #     messagedigest.update(abyte1);
    #   }
      if (abyte1 != nil && abyte1.length > 0)
        messagedigest.update(abyte1)
      end
    #   messagedigest.update( (byte) 2);
      messagedigest.update( 2.chr )
    #   abyte3 = messagedigest.digest();
      abyte3 = messagedigest.digest
    #   System.arraycopy(abyte3, 0, abyte2, byte0, 32 - byte0);
      abyte2[byte0, 32 - byte0] = abyte3[0, 32 - byte0]
    #   return abyte2;
      # puts "<br/>DEBUG y: abyte2=#{abyte2.unpack("H*")[0]}"
      return abyte2
    # }
    end
    
    # private static String z(byte abyte0[]) {
    def z(abyte0)
    # #   if (abyte0 == null) {
    # #     return null;
    # #   }
    #   if (abyte0 == nil)
    #     return nil
    #   end
    # #   String s1 = "0123456789ABCDEF";
    #   s1 = "0123456789ABCDEF"
    # #   StringBuffer stringbuffer = new StringBuffer(abyte0.length * 2);
    #   stringbuffer = ""
    # #   int i1 = 0;
    #   i1 = 0
    # #   for (int j1 = abyte0.length; j1 > 0; ) {
    #   j1 = abyte0.length
    #   while (j1 > 0)
    # #     byte byte0 = abyte0[i1];
    #     byte0 = abyte0[i1]
    # #     stringbuffer.append(s1.charAt(byte0 >> 4 & 0xf));
    #     stringbuffer << s1[byte0 >> 4 & 0xf]
    # #     stringbuffer.append(s1.charAt(byte0 & 0xf));
    #     stringbuffer << s1[byte0 & 0xf]
    # #     j1--;
    #     j1 -= 1
    # #     i1++;
    #     i1 += 1
    # #   }
    #   end
    # # 
    # #   return stringbuffer.toString();
    #   return stringbuffer
    # # }
      abyte0.unpack("H*")[0].upcase
    end

    # private static byte[] A(char ac[]) {
    def a_(ac)
      # RSI: if we receive String then return the same value (as it should already be in UTF-8)
      return ac if ac.is_a? String
    #   byte abyte0[] = new byte[ac.length * 3];
      abyte0 = "\0"*(ac.length * 3)
    #   int i1 = 0;
      i1 = 0
    #   boolean flag = false;
      flag = false
    #   for (int j1 = 0; j1 < ac.length; j1++) {
      for j1 in 0...ac.length
    #     char c1 = ac[j1];
        c1 = ac[j1]
    #     if (c1 >= 0 && c1 <= '\177') {
    #       abyte0[i1++] = (byte) (c1 & 0x7f);
    #     }
        if (c1 >= 0 && c1 <= 0177)
          abyte0[i1] = (c1 & 0x7f)
          i1 += 1
    #     else
    #     if (c1 >= '\200' && c1 <= '\u07FF') {
    #       abyte0[i1++] = (byte) ( (c1 & 0x7c0) >> 6 | 0xc0);
    #       abyte0[i1++] = (byte) (c1 & 0x3f | 0x80);
    #     }
        elsif (c1 >= 0200 && c1 <= 0x07FF)
          abyte0[i1] = ( (c1 & 0x7c0) >> 6 | 0xc0)
          i1 += 1
          abyte0[i1] = (c1 & 0x3f | 0x80)
          i1 += 1
    #     else
    #     if (c1 >= '\u0800' && c1 <= '\uFFFF') {
    #       abyte0[i1++] = (byte) ( (c1 & 0xf000) >> 12 | 0xe0);
    #       abyte0[i1++] = (byte) ( (c1 & 0xfc0) >> 6 | 0x80);
    #       abyte0[i1++] = (byte) (c1 & 0x3f | 0x80);
    #     }
        elsif (c1 >= 0x0800 && c1 <= 0xFFFF)
          abyte0[i1] = ( (c1 & 0xf000) >> 12 | 0xe0)
          i1 += 1
          abyte0[i1] = ( (c1 & 0xfc0) >> 6 | 0x80)
          i1 += 1
          abyte0[i1] = (c1 & 0x3f | 0x80)
          i1 += 1
        end
    #   }
      end
    # 
    #   byte abyte1[] = new byte[i1];
      abyte1 = "\0"*i1
    #   System.arraycopy(abyte0, 0, abyte1, 0, i1);
      abyte1[0, i1] = abyte0[0, i1]
    #   return abyte1;
      abyte1
    # }
    end

    # private static void B(byte abyte0[], byte abyte1[], byte abyte2[], int i1) {
    def b_(abyte0, abyte1, abyte2, i1)
    #   if (abyte0 == null) {
      if (abyte0 == nil)
    #     if (i1 > 0 && abyte1 != null && abyte2 != null) {
        if (i1 > 0 && abyte1 != nil && abyte2 != nil)
    #       for (int j1 = 0; j1 < i1; j1++) {
    #         abyte2[j1] = abyte1[j1];
    # 
    #       }
          for j1 in 0...i1
            abyte2[j1] = abyte1[j1]
          end
    #       return;
          return
    #     }
        end
    #   }
    #   else {
    #     if (abyte2 == null) {
      else
        if (abyte2 == nil)
    #       for (int k1 = 0; k1 < 256; k1++) {
    #         abyte0[k1] = (byte) k1;
    # 
    #       }
          for k1 in 0...256
            abyte0[k1] = k1
          end
    #       if (abyte1 != null && i1 > 0) {
          if (abyte1 != nil && i1 > 0)
    #         int j2 = 0;
            j2 = 0
    #         int l2 = 0;
            l2 = 0
    #         for (int l1 = 0; l1 < 256; l1++) {
    #           int j3 = (new Byte(abyte0[l1])).intValue() & 0xff;
    #           j2 = j2 + j3 + ( (new Byte(abyte1[l2])).intValue() & 0xff) & 0xff;
    #           abyte0[l1] = abyte0[j2];
    #           abyte0[j2] = (new Integer(j3 & 0xff)).byteValue();
    #           l2 = (l2 + 1) % i1;
    #         }
            for l1 in 0...256
              j3 = abyte0[l1] & 0xff
              j2 = j2 + j3 + ( abyte1[l2] & 0xff) & 0xff
              abyte0[l1] = abyte0[j2]
              abyte0[j2] = j3 & 0xff
              l2 = (l2 + 1) % i1
            end
    # 
    #       }
          end
    #       abyte0[256] = 0;
          abyte0[256] = 0
    #       abyte0[257] = 0;
          abyte0[257] = 0
    #       return;
          return
    #     }
        end
    #     int i2 = (new Byte(abyte0[256])).intValue() & 0xff;
        i2 = abyte0[256] & 0xff
    #     int k2 = (new Byte(abyte0[257])).intValue() & 0xff;
        k2 = abyte0[257] & 0xff
    #     for (int i3 = 0; i3 < i1; i3++) {
        for i3 in 0...i1
    #       i2 = i2 + 1 & 0xff;
          i2 = i2 + 1 & 0xff
    #       int k3 = (new Byte(abyte0[i2])).intValue() & 0xff;
          k3 = abyte0[i2] & 0xff
    #       k2 = k2 + k3 & 0xff;
          k2 = k2 + k3 & 0xff
    #       abyte0[i2] = abyte0[k2];
          abyte0[i2] = abyte0[k2]
    #       abyte0[k2] = (new Integer(k3 & 0xff)).byteValue();
          abyte0[k2] = k3 & 0xff
    #       k3 += (new Byte(abyte0[i2])).intValue() & 0xff;
          k3 += abyte0[i2] & 0xff
    #       abyte2[i3] = (byte) (abyte1[i3] ^ abyte0[k3 & 0xff]);
          abyte2[i3] = (abyte1[i3] ^ abyte0[k3 & 0xff])
    #       new String("");
          ""
    #     }
        end
    # 
    #     abyte0[256] = (byte) (i2 & 0xff);
        abyte0[256] = (i2 & 0xff)
    #     abyte0[257] = (byte) (k2 & 0xff);
        abyte0[257] = (k2 & 0xff)
    #   }
      end
    # }
    end

    # static boolean check(String s1, String s2, boolean flag) {
    def check(s1, s2, flag)
      return true if decrypt(s1, s2, flag)
      false
    end
    
    def decrypt(s1, s2, flag)
    #   String cid;
    #   if (s2 != null && s2.length() > 0) {
      if (s2 != nil && s2.length() > 0)
    #     if (s2.substring(0, 2).equals("ZG")) {
    #       cid = newCheck(s1, s2, flag);
    #     }
        if (s2[0, 2] == "ZG")
          # EBEI: Upcase case-insensitive passwords
          cid = new_check(s1.mb_chars.upcase.to_s, s2, flag)
        # EBEI: Support case sensitive passwords in R12
        elsif s2[0, 2] == "ZH"
          cid = new_check(s1, s2.gsub(/^ZH/, 'ZG'), flag)
    #     else {
    #       cid= oldCheck(s1, s2, flag);
    #     }
        else
          cid = old_check(s1, s2, flag)
        end
    #   }
    #   else {
    #     return false;
    #   }
      else
        return false
      end
    #   if (cid==null) {
    #     return false;
    #   } else  {
    #     return true;
    #   }
      return cid
    # }
    end
 
    # private static int[] C(int ai[]) {
    def c_(ai)
    #   int ai1[] = new int[32];
      ai1 = [nil]*32
    #   int ai2[] = ai;
      ai2 = ai
    #   int i1 = 0;
      i1 = 0
    #   boolean flag = false;
      flag = false
    #   int k1 = 0;
      k1 = 0
    #   int l1 = 0;
      l1 = 0
    #   while (i1 < 16) {
      while (i1 < 16)
    #     int j1 = k1++;
        j1 = k1
        k1 += 1
    #     ai1[l1] = (ai2[j1] & 0xfc0000) << 6;
        ai1[l1] = (ai2[j1] & 0xfc0000) << 6
    #     ai1[l1] |= (ai2[j1] & 0xfc0) << 10;
        ai1[l1] |= (ai2[j1] & 0xfc0) << 10
    #     ai1[l1] |= (ai[k1] & 0xfc0000) >> 10;
        ai1[l1] |= (ai[k1] & 0xfc0000) >> 10
    #     ai1[l1] |= (ai[k1] & 0xfc0) >> 6;
        ai1[l1] |= (ai[k1] & 0xfc0) >> 6
    #     l1++;
        l1 += 1
    #     ai1[l1] = (ai2[j1] & 0x3f000) << 12;
        ai1[l1] = (ai2[j1] & 0x3f000) << 12
    #     ai1[l1] |= (ai2[j1] & 0x3f) << 16;
        ai1[l1] |= (ai2[j1] & 0x3f) << 16
    #     ai1[l1] |= (ai[k1] & 0x3f000) >> 4;
        ai1[l1] |= (ai[k1] & 0x3f000) >> 4
    #     ai1[l1] |= ai[k1] & 0x3f;
        ai1[l1] |= ai[k1] & 0x3f
    #     l1++;
        l1 += 1
    #     i1++;
        i1 += 1
    #     k1++;
        k1 += 1
    #   }
      end
    #   return ai1;
      return ai1
    # }
    end

    # private static void D(byte abyte0[], byte abyte1[], byte abyte2[], int i1) {
    def d_(abyte0, abyte1, abyte2, i1)
    #   for (int j1 = 0; j1 < 8; j1++) {
    #     abyte2[j1 + i1] = (byte) (abyte0[j1] ^ abyte1[j1]);
    # 
    #   }
      for j1 in 0...8
        abyte2[j1 + i1] = (abyte0[j1] ^ abyte1[j1])
      end
    # }
    end

    # private static void E(String s1) {
    # }
    def e_(s1)
    end

    # private static void F(int ai[], int ai1[]) {
    def f_(ai, ai1)
    #   int j2 = 0;
      j2 = 0
    #   int l1 = ai[0];
      l1 = ai[0]
    #   int k1 = ai[1];
      k1 = ai[1]
    #   int j1 = (l1 >>> 4 ^ k1) & 0xf0f0f0f;
    # TODO: check that it is safe to replace >>> with >>
      j1 = (l1 >> 4 ^ k1) & 0xf0f0f0f
    #   k1 ^= j1;
      k1 ^= j1
    #   l1 ^= j1 << 4;
      l1 ^= (j1 << 4) & 0xffffffff
    #   j1 = (l1 >>> 16 ^ k1) & 0xffff;
    # TODO: check that it is safe to replace >>> with >>
      j1 = (l1 >> 16 ^ k1) & 0xffff
    #   k1 ^= j1;
      k1 ^= j1
    #   l1 ^= j1 << 16;
      l1 ^= (j1 << 16) & 0xffffffff
    #   j1 = (k1 >>> 2 ^ l1) & 0x33333333;
    # TODO: check that it is safe to replace >>> with >>
      j1 = (k1 >> 2 ^ l1) & 0x33333333
    #   l1 ^= j1;
      l1 ^= j1
    #   k1 ^= j1 << 2;
      k1 ^= (j1 << 2) & 0xffffffff
    #   j1 = (k1 >>> 8 ^ l1) & 0xff00ff;
      j1 = (k1 >> 8 ^ l1) & 0xff00ff
    #   l1 ^= j1;
      l1 ^= j1
    #   k1 ^= j1 << 8;
      k1 ^= (j1 << 8) & 0xffffffff
    #   k1 = (k1 << 1 | k1 >>> 31 & 1) & -1;
    # TODO: check that it is safe to replace >>> with >>
      k1 = (k1 << 1 | k1 >> 31 & 1) & 0xffffffff
    #   j1 = (l1 ^ k1) & 0xaaaaaaaa;
      j1 = (l1 ^ k1) & 0xaaaaaaaa
    #   l1 ^= j1;
      l1 ^= j1
    #   k1 ^= j1;
      k1 ^= j1
    #   l1 = (l1 << 1 | l1 >>> 31 & 1) & -1;
    # TODO: check that it is safe to replace >>> with >>
      l1 = (l1 << 1 | l1 >> 31 & 1) & 0xffffffff
    #   for (int i2 = 0; i2 < 8; i2++) {
      for i2 in 0...8
    #     j1 = k1 << 28 | k1 >>> 4;
    # TODO: check that it is safe to replace >>> with >>
        j1 = (k1 << 28 | k1 >> 4) & 0xffffffff
    #     long l2 = 0L;
    # TODO: check if long integeres are processed automatically
        l2 = 0
    #     l2 = ai1[j2];
        l2 = ai1[j2]
    #     j1 ^= ai1[j2];
        j1 ^= ai1[j2]
    #     j2++;
        j2 += 1
    #     int i1 = bj[j1 & 0x3f];
        i1 = Bj[j1 & 0x3f]
    #     i1 |= L[j1 >>> 8 & 0x3f];
    # TODO: check if long integeres are processed automatically
        i1 |= L[j1 >> 8 & 0x3f]
    #     i1 |= P[j1 >>> 16 & 0x3f];
        i1 |= P[j1 >> 16 & 0x3f]
    #     i1 |= T[j1 >>> 24 & 0x3f];
        i1 |= T[j1 >> 24 & 0x3f]
    #     j1 = k1 ^ ai1[j2];
        j1 = k1 ^ ai1[j2]
    #     j2++;
        j2 += 1
    #     i1 |= bg[j1 & 0x3f];
        i1 |= Bg[j1 & 0x3f]
    #     i1 |= bm[j1 >>> 8 & 0x3f];
        i1 |= Bm[j1 >> 8 & 0x3f]
    #     i1 |= N[j1 >>> 16 & 0x3f];
        i1 |= N[j1 >> 16 & 0x3f]
    #     i1 |= R[j1 >>> 24 & 0x3f];
        i1 |= R[j1 >> 24 & 0x3f]
    #     l1 ^= i1;
        l1 ^= i1
    #     j1 = l1 << 28 | l1 >>> 4;
        j1 = (l1 << 28 | l1 >> 4) & 0xffffffff
    #     j1 ^= ai1[j2];
        j1 ^= ai1[j2]
    #     j2++;
        j2 += 1
    #     i1 = bj[j1 & 0x3f];
        i1 = Bj[j1 & 0x3f]
    #     i1 |= L[j1 >>> 8 & 0x3f];
        i1 |= L[j1 >> 8 & 0x3f]
    #     i1 |= P[j1 >>> 16 & 0x3f];
        i1 |= P[j1 >> 16 & 0x3f]
    #     i1 |= T[j1 >>> 24 & 0x3f];
        i1 |= T[j1 >> 24 & 0x3f]
    #     j1 = l1 ^ ai1[j2];
        j1 = l1 ^ ai1[j2]
    #     j2++;
        j2 += 1
    #     i1 |= bg[j1 & 0x3f];
        i1 |= Bg[j1 & 0x3f]
    #     i1 |= bm[j1 >>> 8 & 0x3f];
        i1 |= Bm[j1 >> 8 & 0x3f]
    #     i1 |= N[j1 >>> 16 & 0x3f];
        i1 |= N[j1 >> 16 & 0x3f]
    #     i1 |= R[j1 >>> 24 & 0x3f];
        i1 |= R[j1 >> 24 & 0x3f]
    #     k1 ^= i1;
        k1 ^= i1
    #   }
      end
    # 
    #   k1 = k1 << 31 | k1 >>> 1;
      k1 = (k1 << 31 | k1 >> 1) & 0xffffffff
    #   j1 = (l1 ^ k1) & 0xaaaaaaaa;
      j1 = (l1 ^ k1) & 0xaaaaaaaa
    #   l1 ^= j1;
      l1 ^= j1
    #   k1 ^= j1;
      k1 ^= j1
    #   l1 = l1 << 31 | l1 >>> 1;
      l1 = l1 << 31 | l1 >> 1
    #   j1 = (l1 >>> 8 ^ k1) & 0xff00ff;
      j1 = (l1 >> 8 ^ k1) & 0xff00ff
    #   k1 ^= j1;
      k1 ^= j1
    #   l1 ^= j1 << 8;
      l1 ^= (j1 << 8) & 0xffffffff
    #   j1 = (l1 >>> 2 ^ k1) & 0x33333333;
      j1 = (l1 >> 2 ^ k1) & 0x33333333
    #   k1 ^= j1;
      k1 ^= j1
    #   l1 ^= j1 << 2;
      l1 ^= (j1 << 2) & 0xffffffff
    #   j1 = (k1 >>> 16 ^ l1) & 0xffff;
      j1 = (k1 >> 16 ^ l1) & 0xffff
    #   l1 ^= j1;
      l1 ^= j1
    #   k1 ^= j1 << 16;
      k1 ^= (j1 << 16) & 0xffffffff
    #   j1 = (k1 >>> 4 ^ l1) & 0xf0f0f0f;
      j1 = (k1 >> 4 ^ l1) & 0xf0f0f0f
    #   l1 ^= j1;
      l1 ^= j1
    #   k1 ^= j1 << 4;
      k1 ^= (j1 << 4) & 0xffffffff
    #   ai[0] = k1;
      ai[0] = k1
    #   ai[1] = l1;
      ai[1] = l1
    # }
    end

    # private static byte[] G(byte abyte0[], byte abyte1[]) {
    def g_(abyte0, abyte1)
    #   if (abyte0.length < 32) {
    #     return null;
    #   }
      if (abyte0.length < 32)
        return nil
      end
    #   byte abyte3[] = new byte[8];
      abyte3 = "\0"*8
    #   byte abyte4[] = new byte[8];
      abyte4 = "\0"*8
    #   byte abyte5[] = new byte[8];
      abyte5 = "\0"*8      
    #   byte abyte2[] = new byte[8];
      abyte2 = "\0"*8
    #   System.arraycopy(abyte0, 0, abyte3, 0, 8);
      abyte3[0, 8] = abyte0[0, 8]
    #   System.arraycopy(abyte0, 8, abyte4, 0, 8);
      abyte4[0, 8] = abyte0[8, 8]
    #   System.arraycopy(abyte0, 16, abyte5, 0, 8);
      abyte5[0, 8] = abyte0[16, 8]
    #   System.arraycopy(abyte0, 24, abyte2, 0, 8);
      abyte2[0, 8] = abyte0[24, 0]
    #   int ai[] = l(abyte3, true);
      ai = l(abyte3, true)
    #   int ai1[] = l(abyte4, false);
      ai1 = l(abyte4, false)
    #   int ai2[] = l(abyte5, true);
      ai2 = l(abyte5, true)
    #   int i1 = abyte1.length % 8;
      i1 = abyte1.length % 8
    #   byte byte0 = (byte) (8 - i1);
      byte0 = (8 - i1)
    #   byte abyte6[] = new byte[abyte1.length + byte0];
      abyte6 = "\0"*(abyte1.length + byte0)
    #   int j1 = abyte6.length / 8 - 1;
      j1 = abyte6.length / 8 - 1
    #   int k1 = 8 * j1;
      k1 = 8 * j1
    #   byte abyte7[] = new byte[8];
      abyte7 = "\0"*8
    #   System.arraycopy(abyte1, k1, abyte7, 0, i1);
      abyte7[0, i1] = abyte1[k1, i1]
    #   for (int l1 = i1; l1 < 8; l1++) {
    #     abyte7[l1] = byte0;
    # 
    #   }
      for l1 in i1...8
        abyte7[l1] = byte0
      end
    #   int i2 = 0;
      i2 = 0
    #   for (int j2 = 0; i2 < j1; j2 += 8) {
    #     q(abyte1, j2, abyte6, j2, ai, ai1, ai2, abyte2, true);
    #     i2++;
    #   }
      j2 = 0
      while (i2 < j1)
        q(abyte1, j2, abyte6, j2, ai, ai1, ai2, abyte2, true)
        i2 += 1
        j2 += 8
      end
    # 
    #   q(abyte7, 0, abyte6, k1, ai, ai1, ai2, abyte2, true);
      q(abyte7, 0, abyte6, k1, ai, ai1, ai2, abyte2, true)
    #   return abyte6;
      return abyte6
    # }
    end

    # private static void H(int ai[]) {
    #   ai[4] = j(ai[0], 5) + r(ai[1], ai[2], ai[3]) + ai[4] + ai[5] + 0x5a827999;
    #   ai[2] = j(ai[1], 30);
    # }
    def h_(ai)
      ai[4] = j(ai[0], 5) + r(ai[1], ai[2], ai[3]) + ai[4] + ai[5] + 0x5a827999
      ai[2] = j(ai[1], 30)
    end

    # private static void I(int ai[]) {
    #   ai[4] = j(ai[0], 5) + n(ai[1], ai[2], ai[3]) + ai[4] + ai[5] + 0x6ed9eba1;
    #   ai[2] = j(ai[1], 30);
    # }
    def i_(ai)
      ai[4] = j(ai[0], 5) + n(ai[1], ai[2], ai[3]) + ai[4] + ai[5] + 0x6ed9eba1
      ai[2] = j(ai[1], 30)
    end

    J = 2
    K = 4

    L = [
        256, 0x2080100, 0x2080000, 0x42000100, 0x80000, 256, 0x40000000,
        0x2080000, 0x40080100, 0x80000,
        0x2000100, 0x40080100, 0x42000100, 0x42080000, 0x80100, 0x40000000,
        0x2000000, 0x40080000, 0x40080000, 0,
        0x40000100, 0x42080100, 0x42080100, 0x2000100, 0x42080000, 0x40000100, 0,
        0x42000000, 0x2080100, 0x2000000,
        0x42000000, 0x80100, 0x80000, 0x42000100, 256, 0x2000000, 0x40000000,
        0x2080000, 0x42000100, 0x40080100,
        0x2000100, 0x40000000, 0x42080000, 0x2080100, 0x40080100, 256, 0x2000000,
        0x42080000, 0x42080100, 0x80100,
        0x42000000, 0x42080100, 0x2080000, 0, 0x40080000, 0x42000000, 0x80100,
        0x2000100, 0x40000100, 0x80000,
        0, 0x40080000, 0x2080100, 0x40000100
    ]
    M = 2
    N = [
        0x802001, 8321, 8321, 128, 0x802080, 0x800081, 0x800001, 8193, 0,
        0x802000,
        0x802000, 0x802081, 129, 0, 0x800080, 0x800001, 1, 8192, 0x800000,
        0x802001,
        128, 0x800000, 8193, 8320, 0x800081, 1, 8320, 0x800080, 8192, 0x802080,
        0x802081, 129, 0x800080, 0x800001, 0x802000, 0x802081, 129, 0, 0,
        0x802000,
        8320, 0x800080, 0x800081, 1, 0x802001, 8321, 8321, 128, 0x802081, 129,
        1, 8192, 0x800001, 8193, 0x802080, 0x800081, 8193, 8320, 0x800000,
        0x802001,
        128, 0x800000, 8192, 0x802080
    ]
    O = 1
    P = [
        520, 0x8020200, 0, 0x8020008, 0x8000200, 0, 0x20208, 0x8000200, 0x20008,
        0x8000008,
        0x8000008, 0x20000, 0x8020208, 0x20008, 0x8020000, 520, 0x8000000, 8,
        0x8020200, 512,
        0x20200, 0x8020000, 0x8020008, 0x20208, 0x8000208, 0x20200, 0x20000,
        0x8000208, 8, 0x8020208,
        512, 0x8000000, 0x8020200, 0x8000000, 0x20008, 520, 0x20000, 0x8020200,
        0x8000200, 0,
        512, 0x20008, 0x8020208, 0x8000200, 0x8000008, 512, 0, 0x8020008,
        0x8000208, 0x20000,
        0x8000000, 0x8020208, 8, 0x20208, 0x20200, 0x8000008, 0x8020000,
        0x8000208, 520, 0x8020000,
        0x20208, 8, 0x8020008, 0x20200
    ]
    Q = 0x8f1bbcdc
    R = [
        0x80108020, 0x80008000, 32768, 0x108020, 0x100000, 32, 0x80100020,
        0x80008020, 0x80000020, 0x80108020,
        0x80108000, 0x80000000, 0x80008000, 0x100000, 32, 0x80100020, 0x108000,
        0x100020, 0x80008020, 0,
        0x80000000, 32768, 0x108020, 0x80100000, 0x100020, 0x80000020, 0,
        0x108000, 32800, 0x80108000,
        0x80100000, 32800, 0, 0x108020, 0x80100020, 0x100000, 0x80008020,
        0x80100000, 0x80108000, 32768,
        0x80100000, 0x80008000, 32, 0x80108020, 0x108020, 32, 32768, 0x80000000,
        32800, 0x80108000,
        0x100000, 0x80000020, 0x100020, 0x80008020, 0x80000020, 0x100020,
        0x108000, 0, 0x80008000, 32800,
        0x80000000, 0x80100020, 0x80108020, 0x108000
    ]
    S = [
        13, 16, 10, 23, 0, 4, 2, 27, 14, 5,
        20, 9, 22, 18, 11, 3, 25, 7, 15, 6,
        26, 19, 12, 1, 40, 51, 30, 36, 46, 54,
        29, 39, 50, 44, 32, 47, 43, 48, 38, 55,
        33, 52, 45, 41, 49, 35, 28, 31
    ]
    T = [
        0x1010400, 0, 0x10000, 0x1010404, 0x1010004, 0x10404, 4, 0x10000, 1024,
        0x1010400,
        0x1010404, 1024, 0x1000404, 0x1010004, 0x1000000, 4, 1028, 0x1000400,
        0x1000400, 0x10400,
        0x10400, 0x1010000, 0x1010000, 0x1000404, 0x10004, 0x1000004, 0x1000004,
        0x10004, 0, 1028,
        0x10404, 0x1000000, 0x10000, 0x1010404, 4, 0x1010000, 0x1010400,
        0x1000000, 0x1000000, 1024,
        0x1010004, 0x10000, 0x10400, 0x1000004, 1024, 4, 0x1000404, 0x10404,
        0x1010404, 0x10004,
        0x1010000, 0x1000404, 0x1000004, 1028, 0x10404, 0x1010400, 1028,
        0x1000400, 0x1000400, 0,
        0x10004, 0x10400, 0, 0x1010004
    ]
    U = 8
    V = [
        56, 48, 40, 32, 24, 16, 8, 0, 57, 49,
        41, 33, 25, 17, 9, 1, 58, 50, 42, 34,
        26, 18, 10, 2, 59, 51, 43, 35, 62, 54,
        46, 38, 30, 22, 14, 6, 61, 53, 45, 37,
        29, 21, 13, 5, 60, 52, 44, 36, 28, 20,
        12, 4, 27, 19, 11, 3
    ]

    W = [
        0x800000, 0x400000, 0x200000, 0x100000, 0x80000, 0x40000, 0x20000,
        0x10000, 32768, 16384,
        8192, 4096, 2048, 1024, 512, 256, 128, 64, 32, 16,
        8, 4, 2, 1
    ]
    X = 0x6ed9eba1
    Y = 8
    Z = 100

    Ba = 32
    Bb = [
        1, 2, 4, 6, 8, 10, 12, 14, 15, 17,
        19, 21, 23, 25, 27, 28
    ]
    Bc = 30
    Bd = "ZG"
    Be = false
    Bf = 0x5a827999
    Bg = [
        0x10001040, 4096, 0x40000, 0x10041040, 0x10000000, 0x10001040, 64,
        0x10000000, 0x40040, 0x10040000,
        0x10041040, 0x41000, 0x10041000, 0x41040, 4096, 64, 0x10040000,
        0x10000040, 0x10001000, 4160,
        0x41000, 0x40040, 0x10040040, 0x10041000, 4160, 0, 0, 0x10040040,
        0x10000040, 0x10001000,
        0x41040, 0x40000, 0x41040, 0x40000, 0x10041000, 4096, 64, 0x10040040,
        4096, 0x41040,
        0x10001000, 64, 0x10000040, 0x10040000, 0x10040040, 0x10000000, 0x40000,
        0x10001040, 0, 0x10041040,
        0x40040, 0x10000040, 0x10040000, 0x10001000, 0x10001040, 0, 0x10041040,
        0x41000, 0x41000, 4160,
        4160, 0x40040, 0x10000000, 0x10041000
    ]
    Bh = 0xca62c1d6
    Bi = [
        -128, 64, 32, 16, 8, 4, 2, 1
    ]
    Bj = [
        0x200000, 0x4200002, 0x4000802, 0, 2048, 0x4000802, 0x200802, 0x4200800,
        0x4200802, 0x200000,
        0, 0x4000002, 2, 0x4000000, 0x4200002, 2050, 0x4000800, 0x200802,
        0x200002, 0x4000800,
        0x4000002, 0x4200000, 0x4200800, 0x200002, 0x4200000, 2048, 2050,
        0x4200802, 0x200800, 2,
        0x4000000, 0x200800, 0x4000000, 0x200800, 0x200000, 0x4000802, 0x4000802,
        0x4200002, 0x4200002, 2,
        0x200002, 0x4000000, 0x4000800, 0x200000, 0x4200800, 2050, 0x200802,
        0x4200800, 2050, 0x4000002,
        0x4200802, 0x4200000, 0x200800, 0, 2, 0x4200802, 0, 0x200802, 0x4200000,
        2048,
        0x4000002, 0x4000800, 2048, 0x200002
    ]
    Bk = "ZG_ENCRYPT_FAILED_"
    Bl = 15
    Bm = [
        0x20000010, 0x20400000, 16384, 0x20404010, 0x20400000, 16, 0x20404010,
        0x400000, 0x20004000, 0x404010,
        0x400000, 0x20000010, 0x400010, 0x20004000, 0x20000000, 16400, 0,
        0x400010, 0x20004010, 16384,
        0x404000, 0x20004010, 16, 0x20400010, 0x20400010, 0, 0x404010, 0x20404000,
        16400, 0x404000,
        0x20404000, 0x20000000, 0x20004000, 16, 0x20400010, 0x404000, 0x20404010,
        0x400000, 16400, 0x20000010,
        0x400000, 0x20004000, 0x20000000, 16400, 0x20000010, 0x20404010, 0x404000,
        0x20400000, 0x404010, 0x20404000,
        0, 0x20400010, 16, 16384, 0x20400000, 0x404010, 16384, 0x400010,
        0x20004010, 0,
        0x20404000, 0x20000000, 0x400010, 0x20004010
    ]

  end

end
