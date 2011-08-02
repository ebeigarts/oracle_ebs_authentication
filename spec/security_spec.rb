# encoding: utf-8

require "spec_helper"

describe "Security" do
  before(:each) do
    @security = OracleEbsAuthentication::Security.new
  end

  it "new_check should return nil if second parameter has encrypt failed message" do
    @security.new_check("XXX", "ZG_ENCRYPT_FAILED_XXX", true).should be_nil
  end

  it "y should return SHA digest" do
    @security.y("user","password").unpack("H*")[0].should == "a79ae8a67c2c3976b82fd25995501524e41c41a129095d06882c4bf7b2c3b782"
  end

  it "z should return hex reprezentation of string" do
    @security.z("\xAA\xBB\xCC").should == "AABBCC"
    @security.z("\x11\x22\x33\x44\x55\x66").should == "112233445566"
  end

  it "a_ should return UTF-8 encoded string" do
    @security.a_("ACEĀČĒaceāčē").should == "ACEĀČĒaceāčē"
  end

  describe "#decrypt and #check" do
    before(:each) do
      @user1 = "ITA_JLAX"
      @password1 = "vaidava1"
      @wrong_password1 = "vaidava2"
      @efp1 = "ZG614D5255C458E576C7E554E62DEFC58ECB33A539100C23FA1089CFCD550CFAC2C4BE9EC42A331C09E0B47B6EB431452C8C"
      @eup1 = "ZGE0E4F7E40CE4586F5765ECD4A0F33A2C0991484F97BBD33F2C32E0A94C307D747363C0DF9816300C896CB5EA1F5EBB33E5"

      @user2 = "ITA_JLAX"
      @password2 = "warcraft3"
      @wrong_password2 = "vaidava2"
      @efp2 = "ZGEC82B1AE4D61E0EAF260B10AD7D557C2469A7EC4E6C9CE3FD77B9C8CEC8AC18FD0EC46DF6D54F94DC602C0BA3F6662C9DF"
      @eup2 = "ZG65C60DF02F55BCCC7BB09BD70C1636C016AA415D486072E671489C0432C3D0CCAF05A0D2DEE7E55E2277356A930145CBA7"

      @user3 = "hrms"
      @password3 = "welcome"
      @wrong_password3 = "welcome1"
      @efp3 = "ZGBC22FF536248A02DC4B4FFAF8CAA1BDFD5564526BBEA23323D67C9BF541291333192D3C89A0447BB6B92FA8C9D272FD67C"

      # R12 case-sensitive passwords
      @user4 = "TESTEBRI"
      @password4 = "R12tester"
      @wrong_password4 = "R12TESTER"
      @efp4 = "ZH6E999CDE99A952A00270CD7DAAEF1392CF1FBC6CFD6AB68EE970FFCEDEC3B88594B0E2A22AD5948B96BDA9B37F246E489C"
    end

    it "should check user1 password" do
      @security.check(@user1.upcase + "/" + @password1.upcase, @efp1, false).should be_true
    end

    it "should not check user1 wrong password" do
      @security.check(@user1.upcase + "/" + @wrong_password1.upcase, @efp1, false).should_not be_true
    end

    it "should compare user1 password with decrypted" do
      apps_password = @security.decrypt(@user1.upcase + "/" + @password1.upcase, @efp1, false)
      # puts "</br>DEBUG: apps_password=#{apps_password}"
      @security.decrypt(apps_password, @eup1, false).should == @password1.upcase
    end

    it "should check user2 password" do
      @security.check(@user2.upcase + "/" + @password2.upcase, @efp2, false).should be_true
    end

    it "should not check user2 wrong password" do
      @security.check(@user2.upcase + "/" + @wrong_password2.upcase, @efp2, false).should_not be_true
    end

    it "should compare user2 password with decrypted" do
      apps_password = @security.decrypt(@user2.upcase + "/" + @password2.upcase, @efp2, false)
      @security.decrypt(apps_password, @eup2, false).should == @password2.upcase
    end

    it "should check user3 password" do
      @security.check(@user3.upcase + "/" + @password3.upcase, @efp3, false).should be_true
    end

    it "should not check user3 wrong password" do
      @security.check(@user3.upcase + "/" + @wrong_password3.upcase, @efp3, false).should_not be_true
    end

    it "should check user4 password" do
      @security.check(@user4.upcase + "/" + @password4, @efp4, false).should be_true
    end

    it "should not check user4 wrong password" do
      @security.check(@user4.upcase + "/" + @wrong_password4, @efp4, false).should_not be_true
    end
  end
end
