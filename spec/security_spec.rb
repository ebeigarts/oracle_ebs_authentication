require File.dirname(__FILE__) + '/spec_helper'
require File.dirname(__FILE__) + '/../lib/security'

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
    @security.a_("ACEĀČĒaceāčē".chars).should == "ACEĀČĒaceāčē"
    @security.a_("ACEĀČĒaceāčē").should == "ACEĀČĒaceāčē"
  end

end

describe "Check user password" do

  before(:each) do
    @security = OracleEbsAuthentication::Security.new
    @user1 = "hrms"
    @password1 = "welcome"
    @wrong_password1 = "welcome1"
    @efp1 = "ZGBC22FF536248A02DC4B4FFAF8CAA1BDFD5564526BBEA23323D67C9BF541291333192D3C89A0447BB6B92FA8C9D272FD67C"
    @eup1 = "ZGB3C85074CA1F57F1A2404FD0717F913530C98D655A54515E5A34A19F7E3348D0D30034EC5B3D5DADAF2747EA90ABDACC64"
  end
  
  it "should check user1 password" do
    @security.check(@user1.upcase + "/" + @password1.upcase, @efp1, false).should be_true
  end
  
  it "should not check user1 wrong password" do
    @security.check(@user1.upcase + "/" + @wrong_password1.upcase, @efp1, false).should_not be_true
  end
  
  it "should compare user1 password with decrypted" do
    apps_password = @security.decrypt(@user1.upcase + "/" + @password1.upcase, @efp1, false)
    @security.decrypt(apps_password, @eup1, false).should == @password1.upcase
  end

end
