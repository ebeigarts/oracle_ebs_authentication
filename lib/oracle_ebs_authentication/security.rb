require "digest/sha1"

module OracleEbsAuthentication
  # The Java original source code was taken form
  # http://code.google.com/p/jebusinessauth/source/browse/trunk/src/com/milci/ebusinesssuite/eBusinessSuiteSecurity.java
  # 
  # As original Java source is not documented then Ruby source code was done
  # as similar as possible to Java code to avoid differences in functionality.
  # 
  class Security
    def initialize
    end

    def control(s1, i1, s2)
      return new_control(s1, s2, i1, 0)
    end

    def a(abyte0, i1)
      ai = [nil]*16
      ai1 = [nil]*5
      u(ai1, nil)
      l1 = ai.length
      k1 = 0
      j2 = 0
      j1 = 0
      while j1 < (i1 & -4)
        ai[k1] = (abyte0[j2] | abyte0[j2 + 1] << 8 | abyte0[j2 + 2] << 16 |
            abyte0[j2 + 3] << 24) & 0xffffffff
        k1 +=1
        if (k1 == l1)
          u(ai1, ai)
          k1 = 0
        end
        j2 += 4
        j1 += 4
      end
      j1 = i1 - j1
      if (j1 == 1)
        ai[k1] = abyte0[j2] & 0xff | 0x8000
      elsif (j1 == 2)
        ai[k1] = (abyte0[j2] | abyte0[j2 + 1] << 8 | 0x800000) & 0xffffffff
      elsif (j1 == 3)
        ai[k1] = (abyte0[j2] | abyte0[j2 + 1] << 8 | abyte0[j2 + 2] << 16 | 0x80000000) & 0xffffffff
      else
        ai[k1] = 128
      end
      k1 += 1
      if (k1 >= l1 - 2)
        while (k1 < l1)
          ai[k1] = 0
          k1 += 1
        end
        u(ai1,ai)
        k1 = 0
      end
      while (k1 < l1 - 2)
        ai[k1] = 0
        k1 += 1
      end
      i2 = i1
      ai[k1] = i2 >> 29 & 7
      k1 += 1
      ai[k1] = (i2 << 3) & 0xffffffff
      u(ai1, ai)
      return ai1
    end

    def new_check(s1, s2, flag)
      if (s1 == nil || s2 == nil ||
          s2.length >= "ZG_ENCRYPT_FAILED_".length &&
          s2[0, "ZG_ENCRYPT_FAILED_".length] == "ZG_ENCRYPT_FAILED_")
        return nil
      end
      abyte0 = s1.dup
      l2 = abyte0.length
      i3 = s2.length
      i1 = 1
      byte0 = 2
      j1 = i3 - 2 - i1 * 2
      if (j1 <= 0)
        return nil
      end
      k1 = (j1 / 16) * 8
      if (k1 <= 0)
        return nil
      end
      l1 = (j1 % 16) / 2
      i2 = l1 + i1
      j2 = k1 - 1 - byte0
      if (j2 <= 0)
        return nil
      end
      if (not s2[0, 2] == "ZG")
        return nil
      end
      s3 = s2[2..-1]
      abyte1 = p(s3)
      abyte2 = "\0"*(abyte1.length - i2)
      abyte3 = "\0"*i2
      abyte2[0, abyte1.length - i2] = abyte1[0, abyte1.length - i2]
      abyte3[0, i2] = abyte1[abyte1.length - i2, i2]
      abyte4 = "\0"*(i2 + l2)
      abyte4[0, i2] = abyte3[0, i2]
      abyte4[i2, l2] = abyte0[0, l2]
      # puts "<br/>DEBUG new_check: abyte4=#{abyte4.inspect} abyte2=#{abyte2.unpack("H*")[0]}"
      abyte5 = v(nil, abyte4, abyte2)
      if (abyte5 == nil)
        # puts "<br/>DEBUG new_check: :nil6"
        return nil
      end
      j3 = abyte5.length
      for k2 in byte0...abyte5.length
        if (abyte5[k2] != 0)
          next
        end
        j3 = k2
        break
      end
      abyte6 = "\0"*(j3 - byte0)
      abyte6[0, j3 - byte0] = abyte5[byte0, j3 - byte0]
      s4 = abyte6
      if (s4 != nil && flag)
        return w(s4, 0, flag)
      else
        return s4
      end
    end

    def c(ai)
      ai[4] = j(ai[0], 5) + s(ai[1], ai[2], ai[3]) + ai[4] + ai[5] + 0x8f1bbcdc
      ai[2] = j(ai[1], 30)
    end

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

    def g(abyte0, abyte1)
      if (abyte0.length < 32)
        # puts "<br/>DEBUG g: nil1"
        return nil
      end
      if (abyte1.length % 8 != 0)
        # puts "<br/>DEBUG g: nil2"
        return nil
      end
      i1 = abyte1.length / 8
      abyte3 = "\0"*8
      abyte4 = "\0"*8
      abyte5 = "\0"*8
      abyte2 = "\0"*8
      abyte3[0,8] = abyte0[0, 8]
      abyte4[0,8] = abyte0[8, 8]
      abyte5[0,8] = abyte0[16, 8]
      abyte2[0,8] = abyte0[24, 8]
      ai = l(abyte3, false)
      ai1 = l(abyte4, true)
      ai2 = l(abyte5, false)
      abyte6 = "\0"*(abyte1.length)
      j1 = 0
      k1 = 0
      while (j1 < i1)
        q(abyte1, k1, abyte6, k1, ai, ai1, ai2, abyte2, false)
        # puts "<br/>DEBUG g: after q() abyte6=#{abyte6.unpack("H*")[0]}"
        j1 += 1
        k1 += 8
      end
      byte0 = abyte6[abyte1.length - 1]
      # puts "<br/>DEBUG g: abyte1=#{abyte1.unpack("H*")[0]}"
      # puts "<br/>DEBUG g: abyte1.length=#{abyte1.length}"
      # puts "<br/>DEBUG g: abyte6=#{abyte6.unpack("H*")[0]}"
      if (byte0 < 1 || byte0 > 8)
        # puts "<br/>DEBUG g: nil3"
        # puts "<br/>DEBUG g: byte0=#{byte0}"
        return nil
      end
      for l1 in (abyte1.length-byte0)...abyte1.length
        if (abyte6[l1] != byte0)
          # puts "<br/>DEBUG g: nil4"
          return nil
        end
      end
      abyte7 = "\0"*(abyte1.length - byte0)
      abyte7[0, abyte1.length - byte0] = abyte6[0, abyte1.length - byte0]
      # puts "<br/>DEBUG g: abyte7=#{abyte7.unpack("H*")[0]}"
      return abyte7
    end

    def h(ai)
      ai[4] = j(ai[0], 5) + o(ai[1], ai[2], ai[3]) + ai[4] + ai[5] + 0xca62c1d6
      ai[2] = j(ai[1], 30)
    end

    def i(abyte0, abyte1, abyte2)
      return g_(y(abyte0, abyte1), abyte2)
    end

    def j(i1, j1)
      return (i1 << j1 | i1 >> 32 - j1) & 0xffffffff
    end

    def k(abyte0, abyte1, i1)
      if (abyte0 == nil || abyte1 == nil)
        return nil
      else
        ai = a(abyte0, abyte0.length)
        abyte2 = e(ai)
        abyte3 = "\0"*258
        b_(abyte3, abyte2, nil, 5)
        abyte4 = "\0"*i1
        b_(abyte3, abyte1, abyte4, i1)
        return abyte4
      end
    end

    def l(abyte0, flag)
      abyte1 = "\0"*56
      abyte2 = "\0"*56
      ai = [nil]*32
      # TODO: check impact of >>> substitution with >>
      for j1 in 0...56
        byte0 = V[j1]
        l2 = byte0 & 7
        abyte1[j1] = ( (abyte0[byte0 >> 3] & Bi[l2]) == 0 ? 0 : 1)
      end
      for i1 in 0...16
        if (flag)
          i3 = i1 << 1
        else
          i3 = 15 - i1 << 1
        end
        j3 = i3 + 1
        ai[i3] = ai[j3] = 0
        for k1 in 0...28
          j2 = k1 + Bb[i1]
          if (j2 < 28)
            abyte2[k1] = abyte1[j2]
          else
            abyte2[k1] = abyte1[j2 - 28]
          end
        end
        for l1 in 28...56
          k2 = l1 + Bb[i1]
          if (k2 < 56)
            abyte2[l1] = abyte1[k2]
          else
            abyte2[l1] = abyte1[k2 - 28]
          end
        end
        for i2 in 0...24
          if (abyte2[S[i2]] != 0)
            ai[i3] |= W[i2]
          end
          if (abyte2[S[i2 + 24]] != 0)
            ai[j3] |= W[i2]
          end
        end
      end
      return c_(ai)
    end

    def old_control(s1, s2, i1)
      if (s1 == nil || s2 == nil)
        return nil
      end
      abyte0 = a_(s1.dup)
      #j1 = s2.mb_chars.length
      j1 = s2.length
      
      if (j1 > i1 - 1)
        j1 = i1 - 1
      end
      k1 = i1 - j1 - 1
      ai = [nil]*k1
      # TODO: substitute Java random.nextInt() with ruby
      for l1 in 0..k1
        # simulation of random.nextInt()
        ai[l1] = rand(2**32)-2**31
      end
      abyte1 = e(ai)
      abyte2 = a_( (s2 + "\0") )
      abyte3 = "\0"*(k1 + abyte2.length)
      abyte3[0, abyte2.length] = abyte2[0, abyte2.length]
      abyte3[abyte2.length, k1] = abyte1[0, k1]
      abyte4 = k(abyte0, abyte3, i1)
      return z(abyte4)
    end

    def m(abyte0)
      while true
        if (abyte0 == nil)
          return nil
        end
        ac = "\0"*(abyte0.length)
        i1 = 0
        flag = false
        flag1 = false
        ac1 = nil
        begin
          break_value = for j1 in 0...abyte0.length do
            byte0 = abyte0[j1]
            if ( (byte0 & 0x80) == 0)
              ac[i1] = byte0
              i1 += 1
              if ( byte0 == 0)
                break
              end
              next
            end
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
            if ( (byte0 & 0xf0) != 224)
              continue
            end
            c2 = ( (byte0 & 0xf) << 12 & 0xf000)
            j1 += 1
            byte0 = abyte0[j1]
            if ( (byte0 & 0x80) != 128)
              break :label0
            end
            c2 |= (byte0 & 0x3f) << 6 & 0xfc0
            j1 += 1
            byte0 = abyte0[j1]
            if ( (byte0 & 0x80) != 128)
              break :label0
            end
            c2 |= byte0 & 0x3f
            ac[i1] = c2
            i1 += 1
          end
          # RSI: jump back to label0 if brake was called with :label0
          if break_value == :label0
            next
          end
          ac1 = "\0"*i1
          ac1[0,i1] = ac[0,i1]
        end
        return ac1
      end
    end


    def n(i1, j1, k1)
      return i1 ^ j1 ^ k1
    end
    
    def o(i1, j1, k1)
      return i1 ^ j1 ^ k1
    end

    def control(s1, s2, i1)
      return new_control(s1, s2, 0, i1)
    end
    
    def p(s1)
      flag = false
      flag1 = false
      i1 = 0
      j1 = 0
      abyte0 = nil
      if (s1 == nil)
        return nil
      end
      k1 = s1.length / 2
      if (k1 > 0)
        abyte0 = "\0"*k1
        while (k1 > 0)
          #c1 = s1.chars[i1]
          c1 = s1[i1]
          i1 += 1
          #c2 = s1.chars[i1]
          c2 = s1[i1]
          i1 += 1
          abyte0[j1] = (f(c1) << 4 | f(c2)) & 0xffffffff
          j1 += 1
          k1 -= 1
        end
      end
      return abyte0
    end

    def q(abyte0, i1, abyte1, j1, ai,
          ai1, ai2, abyte2,
          flag)
      abyte3 = "\0"*8
      abyte3[0, 8] = abyte0[i1, 8]
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
      else
        d_(abyte3, abyte2, abyte3, 0);
        d(abyte3, ai);
        d(abyte3, ai1);
        d(abyte3, ai2);
        abyte2[0, 8] = abyte3[0, 8]
        abyte1[j1, 8] = abyte3[0, 8]
        return
      end
    end

    def r(i1, j1, k1)
      return i1 & j1 | ~i1 & k1
    end

    def s(i1, j1, k1)
      return i1 & j1 | i1 & k1 | j1 & k1
    end

    def hash(s1)
      if (s1 == nil)
        return nil
      end
      abyte0 = s1.dup
      abyte1 = y(nil, abyte0)
      return z(abyte1)
    end

    def new_control(s1, s2, i1, j1)
      if (s1 == nil || s2 == nil)
        return "ZG_ENCRYPT_FAILED_BADINPUT"
      end
      if (i1 > 0)
        k1 = i1
      elsif (j1 == 32)
        k1 = 100
      elsif (j1 < 32 && j1 == s2.length())
        k1 = 100
      else
        abyte1 = s2.dup
        k1 = ( (abyte1.length + 10) / 8) * 16 + 4 + 14
      end
      l1 = 1
      byte0 = 2
      i2 = k1 - 2 - l1 * 2
      if (i2 <= 0)
        return "ZG_ENCRYPT_FAILED_SMALLBUF"
      end
      j2 = (i2 / 16) * 8
      if (j2 <= 0)
        return "ZG_ENCRYPT_FAILED_SMALLBUF"
      end
      k2 = (i2 % 16) / 2
      l2 = k2 + l1
      i3 = j2 - 1 - byte0
      if (i3 <= 0)
        return "ZG_ENCRYPT_FAILED_SMALLBUF"
      end
      abyte0 = s1.dup
      abyte2 = s2.dup
      j3 = abyte0.length
      k3 = abyte2.length
      if (k3 > i3)
        return "ZG_ENCRYPT_FAILED_CHARSET_CLIP"
      end
      ai = [nil]*l2
      for l3 in 0...l2
        ai[l3] = rand(2**32)-2**31
      end
      abyte3 = e(ai)
      ai = nil
      byte1 = byte0
      ai = [nil]*byte1
      for i4 in 0...byte1
        ai[i4] = rand(2**32)-2**31
      end
      abyte4 = e(ai)
      ai = nil
      j4 = i3 - k3
      ai = [nil]*j4
      for k4 in 0...j4
        if (k4 == 0)
          ai[k4] = 0
        else
          ai[k4] = rand(2**32)-2**31
        end
      end
      abyte5 = e(ai)
      ai = nil
      abyte6 = "\0"*(byte1 + j4 + k3)
      abyte6[0, byte1] = abyte4[0, byte1]
      abyte6[byte1, k3] = abyte2[0, k3]
      abyte6[byte1+k3, j4] = abyte5[0, j4]
      abyte7 = "\0"*(l2 + j3)
      abyte7[0, l2] = abyte3[0, l2]
      abyte7[l2, j3] = abyte0[0, j3]
      abyte8 = i(nil, abyte7, abyte6)
      if (abyte8 == nil)
        return "ZG_ENCRYPT_FAILED_MISC"
      else
        abyte9 = "\0"*(abyte8.length + l2)
        abyte9[0, abyte8.length] = abyte8[0, abyte8.length]
        abyte9[abyte8.length, l2] = abyte3[0, l2]
        s3 = z(abyte9)
        return "ZG" + s3
      end
    end

    def t(abyte0, ai)
      i1 = 0
      ai[0] = ((abyte0[i1] & 0xff) << 24)  & 0xffffffff
      i1 += 1
      ai[0] |= ((abyte0[i1] & 0xff) << 16) & 0xffffffff
      i1 += 1
      ai[0] |= ((abyte0[i1] & 0xff) << 8) & 0xffffffff
      i1 += 1
      ai[0] |= abyte0[i1] & 0xff
      i1 += 1
      ai[1] = ((abyte0[i1] & 0xff) << 24) & 0xffffffff
      i1 += 1
      ai[1] |= ((abyte0[i1] & 0xff) << 16) & 0xffffffff
      i1 += 1
      ai[1] |= ((abyte0[i1] & 0xff) << 8) & 0xffffffff
      i1 += 1
      ai[1] |= abyte0[i1] & 0xff
    end

    def u(ai, ai1)
      flag = false
      flag1 = false
      ai2 = [nil]*80
      l1 = 0
      ai3 = [nil]*5
      ai4 = [nil]*6
      ai5 = [nil]*5
      ai3[0] = 0x67452301
      ai3[1] = 0xefcdab89
      ai3[2] = 0x98badcfe
      ai3[3] = 0x10325476
      ai3[4] = 0xc3d2e1f0
      if (ai1 != nil)
        if (ai != nil)
          ai4[0, 5] = ai[0, 5]
        end
        byte0 = 80
        for i1 in 0...16
          ai2[i1] = ai1[i1]
        end
        while (i1 < byte0)
          ai2[i1] = ai2[i1 - 3] ^ ai2[i1 - 8] ^ ai2[i1 - 14] ^ ai2[i1 - 16]
          i1 += 1
        end
        for j1 in 0...80
          if (j1 != 0)
            ai5[0, 5] = ai4[0, 5]
            ai4[0] = ai5[4];
            ai4[1] = ai5[0];
            ai4[2] = ai5[1];
            ai4[3] = ai5[2];
            ai4[4] = ai5[3];
          end
          ai4[5] = ai2[j1]
          if (j1 < 20)
            h_(ai4)
          elsif (j1 < 40)
            i_(ai4)
          elsif (j1 < 60)
            c(ai4)
          elsif (j1 < 80)
            h(ai4)
          end
        end
        ai3[0] = ai4[4];
        ai3[1] = ai4[0];
        ai3[2] = ai4[1];
        ai3[3] = ai4[2];
        ai3[4] = ai4[3];
        for k1 in 0...byte0
          ai2[k1] = 0
        end
      end
      if (ai != nil)
        ai[0] = ai3[0];
        ai[1] = ai3[1];
        ai[2] = ai3[2];
        ai[3] = ai3[3];
        ai[4] = ai3[4];
      end
      l1 = ai3[0] ^ ai3[1] ^ ai3[2] ^ ai3[3] ^ ai3[4]
      return l1
    end

    def v(abyte0, abyte1, abyte2)
      return g(y(abyte0, abyte1), abyte2)
    end

    def w(s1, i1, flag)
      if (s1 == nil)
        return ""
      end
      j1 = s1.length
      k1 = s1.index("\0")
      if (k1 > -1)
        j1 = k1
      end
      if (j1 > i1 && i1 > 0)
        l1 = i1
      else
        l1 = j1
      end
      if (flag)
        # TODO: should we do Unicode upcase?
        return s1[0, l1].upcase
      else
        return s1[0, l1]
      end
    end

    def x(ai, abyte0)
      i1 = 0
      abyte0[i1] = (ai[0] >> 24 & 0xff)
      i1 += 1
      abyte0[i1] = (ai[0] >> 16 & 0xff)
      i1 += 1
      abyte0[i1] = (ai[0] >> 8 & 0xff)
      i1 += 1
      abyte0[i1] = (ai[0] & 0xff)
      i1 += 1
      abyte0[i1] = (ai[1] >> 24 & 0xff)
      i1 += 1
      abyte0[i1] = (ai[1] >> 16 & 0xff)
      i1 += 1
      abyte0[i1] = (ai[1] >> 8 & 0xff)
      i1 += 1
      abyte0[i1] = (ai[1] & 0xff)
    end
    
    def old_check(s1, s2, flag)
      abyte0 = a_(s1.dup)
      abyte1 = p(s2)
      abyte2 = k(abyte0, abyte1, abyte1.length)
      ac = m(abyte2)
      if (ac != nil)
        s3 = ac.to_s
      else
        return nil
      end
    end

    def y(abyte0, abyte1)
      # puts "<br/>DEBUG y: abyte0=#{abyte0.nil? ? "nil" : abyte0.unpack("H*")[0]}"
      # puts "<br/>DEBUG y: abyte1=#{abyte1.nil? ? "nil" : abyte1.unpack("H*")[0]}"
      abyte2 = "\0"*32
      messagedigest = Digest::SHA1.new
      messagedigest.reset
      byte0 = 20
      if (abyte0 != nil && abyte0.length > 0)
        messagedigest.update(abyte0)
      end
      if (abyte1 != nil && abyte1.length > 0)
        messagedigest.update(abyte1)
      end
      messagedigest.update(1.chr)
      abyte3 = messagedigest.digest
      # puts "<br/>DEBUG y: abyte3=#{abyte3.nil? ? "nil" : abyte3.unpack("H*")[0]}"
      abyte2[0, byte0] = abyte3[0, byte0]
      messagedigest.reset()
      if (abyte0 != nil && abyte0.length > 0)
        messagedigest.update(abyte0)
      end
      if (abyte1 != nil && abyte1.length > 0)
        messagedigest.update(abyte1)
      end
      messagedigest.update( 2.chr )
      abyte3 = messagedigest.digest
      abyte2[byte0, 32 - byte0] = abyte3[0, 32 - byte0]
      # puts "<br/>DEBUG y: abyte2=#{abyte2.unpack("H*")[0]}"
      return abyte2
    end
    
    def z(abyte0)
      abyte0.unpack("H*")[0].upcase
    end

    def a_(ac)
      # RSI: if we receive String then return the same value (as it should already be in UTF-8)
      return ac if ac.is_a? String
      abyte0 = "\0"*(ac.length * 3)
      i1 = 0
      flag = false
      for j1 in 0...ac.length
        c1 = ac[j1]
        if (c1 >= 0 && c1 <= 0177)
          abyte0[i1] = (c1 & 0x7f)
          i1 += 1
        elsif (c1 >= 0200 && c1 <= 0x07FF)
          abyte0[i1] = ( (c1 & 0x7c0) >> 6 | 0xc0)
          i1 += 1
          abyte0[i1] = (c1 & 0x3f | 0x80)
          i1 += 1
        elsif (c1 >= 0x0800 && c1 <= 0xFFFF)
          abyte0[i1] = ( (c1 & 0xf000) >> 12 | 0xe0)
          i1 += 1
          abyte0[i1] = ( (c1 & 0xfc0) >> 6 | 0x80)
          i1 += 1
          abyte0[i1] = (c1 & 0x3f | 0x80)
          i1 += 1
        end
      end
      abyte1 = "\0"*i1
      abyte1[0, i1] = abyte0[0, i1]
      abyte1
    end

    def b_(abyte0, abyte1, abyte2, i1)
      if (abyte0 == nil)
        if (i1 > 0 && abyte1 != nil && abyte2 != nil)
          for j1 in 0...i1
            abyte2[j1] = abyte1[j1]
          end
          return
        end
      else
        if (abyte2 == nil)
          for k1 in 0...256
            abyte0[k1] = k1
          end
          if (abyte1 != nil && i1 > 0)
            j2 = 0
            l2 = 0
            for l1 in 0...256
              j3 = abyte0[l1] & 0xff
              j2 = j2 + j3 + ( abyte1[l2] & 0xff) & 0xff
              abyte0[l1] = abyte0[j2]
              abyte0[j2] = j3 & 0xff
              l2 = (l2 + 1) % i1
            end
          end
          abyte0[256] = 0
          abyte0[257] = 0
          return
        end
        i2 = abyte0[256] & 0xff
        k2 = abyte0[257] & 0xff
        for i3 in 0...i1
          i2 = i2 + 1 & 0xff
          k3 = abyte0[i2] & 0xff
          k2 = k2 + k3 & 0xff
          abyte0[i2] = abyte0[k2]
          abyte0[k2] = k3 & 0xff
          k3 += abyte0[i2] & 0xff
          abyte2[i3] = (abyte1[i3] ^ abyte0[k3 & 0xff])
          ""
        end
        abyte0[256] = (i2 & 0xff)
        abyte0[257] = (k2 & 0xff)
      end
    end

    def check(s1, s2, flag)
      return true if decrypt(s1, s2, flag)
      false
    end
    
    def decrypt(s1, s2, flag)
      if (s2 != nil && s2.length() > 0)
        if (s2[0, 2] == "ZG")
          # EBEI: Upcase case-insensitive passwords
          cid = new_check(s1.mb_chars.upcase.to_s, s2, flag)
        # EBEI: Support case sensitive passwords in R12
        elsif s2[0, 2] == "ZH"
          cid = new_check(s1, s2.gsub(/^ZH/, 'ZG'), flag)
        else
          cid = old_check(s1, s2, flag)
        end
      else
        return false
      end
      return cid
    end

    def c_(ai)
      ai1 = [nil]*32
      ai2 = ai
      i1 = 0
      flag = false
      k1 = 0
      l1 = 0
      while (i1 < 16)
        j1 = k1
        k1 += 1
        ai1[l1] = (ai2[j1] & 0xfc0000) << 6
        ai1[l1] |= (ai2[j1] & 0xfc0) << 10
        ai1[l1] |= (ai[k1] & 0xfc0000) >> 10
        ai1[l1] |= (ai[k1] & 0xfc0) >> 6
        l1 += 1
        ai1[l1] = (ai2[j1] & 0x3f000) << 12
        ai1[l1] |= (ai2[j1] & 0x3f) << 16
        ai1[l1] |= (ai[k1] & 0x3f000) >> 4
        ai1[l1] |= ai[k1] & 0x3f
        l1 += 1
        i1 += 1
        k1 += 1
      end
      return ai1
    end

    def d_(abyte0, abyte1, abyte2, i1)
      for j1 in 0...8
        abyte2[j1 + i1] = (abyte0[j1] ^ abyte1[j1])
      end
    end

    def e_(s1)
    end

    def f_(ai, ai1)
      j2 = 0
      l1 = ai[0]
      k1 = ai[1]
      j1 = (l1 >> 4 ^ k1) & 0xf0f0f0f
      k1 ^= j1
      l1 ^= (j1 << 4) & 0xffffffff
      j1 = (l1 >> 16 ^ k1) & 0xffff
      k1 ^= j1
      l1 ^= (j1 << 16) & 0xffffffff
      j1 = (k1 >> 2 ^ l1) & 0x33333333
      l1 ^= j1
      k1 ^= (j1 << 2) & 0xffffffff
      j1 = (k1 >> 8 ^ l1) & 0xff00ff
      l1 ^= j1
      k1 ^= (j1 << 8) & 0xffffffff
      k1 = (k1 << 1 | k1 >> 31 & 1) & 0xffffffff
      j1 = (l1 ^ k1) & 0xaaaaaaaa
      l1 ^= j1
      k1 ^= j1
      l1 = (l1 << 1 | l1 >> 31 & 1) & 0xffffffff
      for i2 in 0...8
        j1 = (k1 << 28 | k1 >> 4) & 0xffffffff
        l2 = 0
        l2 = ai1[j2]
        j1 ^= ai1[j2]
        j2 += 1
        i1 = Bj[j1 & 0x3f]
        i1 |= L[j1 >> 8 & 0x3f]
        i1 |= P[j1 >> 16 & 0x3f]
        i1 |= T[j1 >> 24 & 0x3f]
        j1 = k1 ^ ai1[j2]
        j2 += 1
        i1 |= Bg[j1 & 0x3f]
        i1 |= Bm[j1 >> 8 & 0x3f]
        i1 |= N[j1 >> 16 & 0x3f]
        i1 |= R[j1 >> 24 & 0x3f]
        l1 ^= i1
        j1 = (l1 << 28 | l1 >> 4) & 0xffffffff
        j1 ^= ai1[j2]
        j2 += 1
        i1 = Bj[j1 & 0x3f]
        i1 |= L[j1 >> 8 & 0x3f]
        i1 |= P[j1 >> 16 & 0x3f]
        i1 |= T[j1 >> 24 & 0x3f]
        j1 = l1 ^ ai1[j2]
        j2 += 1
        i1 |= Bg[j1 & 0x3f]
        i1 |= Bm[j1 >> 8 & 0x3f]
        i1 |= N[j1 >> 16 & 0x3f]
        i1 |= R[j1 >> 24 & 0x3f]
        k1 ^= i1
      end
      k1 = (k1 << 31 | k1 >> 1) & 0xffffffff
      j1 = (l1 ^ k1) & 0xaaaaaaaa
      l1 ^= j1
      k1 ^= j1
      l1 = l1 << 31 | l1 >> 1
      j1 = (l1 >> 8 ^ k1) & 0xff00ff
      k1 ^= j1
      l1 ^= (j1 << 8) & 0xffffffff
      j1 = (l1 >> 2 ^ k1) & 0x33333333
      k1 ^= j1
      l1 ^= (j1 << 2) & 0xffffffff
      j1 = (k1 >> 16 ^ l1) & 0xffff
      l1 ^= j1
      k1 ^= (j1 << 16) & 0xffffffff
      j1 = (k1 >> 4 ^ l1) & 0xf0f0f0f
      l1 ^= j1
      k1 ^= (j1 << 4) & 0xffffffff
      ai[0] = k1
      ai[1] = l1
    end

    def g_(abyte0, abyte1)
      if (abyte0.length < 32)
        return nil
      end
      abyte3 = "\0"*8
      abyte4 = "\0"*8
      abyte5 = "\0"*8
      abyte2 = "\0"*8
      abyte3[0, 8] = abyte0[0, 8]
      abyte4[0, 8] = abyte0[8, 8]
      abyte5[0, 8] = abyte0[16, 8]
      abyte2[0, 8] = abyte0[24, 0]
      ai = l(abyte3, true)
      ai1 = l(abyte4, false)
      ai2 = l(abyte5, true)
      i1 = abyte1.length % 8
      byte0 = (8 - i1)
      abyte6 = "\0"*(abyte1.length + byte0)
      j1 = abyte6.length / 8 - 1
      k1 = 8 * j1
      abyte7 = "\0"*8
      abyte7[0, i1] = abyte1[k1, i1]
      for l1 in i1...8
        abyte7[l1] = byte0
      end
      i2 = 0
      j2 = 0
      while (i2 < j1)
        q(abyte1, j2, abyte6, j2, ai, ai1, ai2, abyte2, true)
        i2 += 1
        j2 += 8
      end
      q(abyte7, 0, abyte6, k1, ai, ai1, ai2, abyte2, true)
      return abyte6
    end

    def h_(ai)
      ai[4] = j(ai[0], 5) + r(ai[1], ai[2], ai[3]) + ai[4] + ai[5] + 0x5a827999
      ai[2] = j(ai[1], 30)
    end

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
