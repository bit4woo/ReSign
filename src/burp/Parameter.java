package burp;

public class Parameter implements IParameter{
	String name;
	String value;
	byte type;
	

    public static byte PARAM_Header = 7;

    public Parameter(String name,String vaule,byte type) {
    	this.name = name;
    	this.value = vaule;
    	this.type = type;
    }
	@Override
	public byte getType() {
		return type;
	}

	@Override
	public String getName() {
		return name;
	}

	@Override
	public String getValue() {
		return value;
	}
	
	@Override
	public int getNameStart() {
		// TODO Auto-generated method stub
		return 0;
	}
	@Override
	public int getNameEnd() {
		// TODO Auto-generated method stub
		return 0;
	}
	@Override
	public int getValueStart() {
		// TODO Auto-generated method stub
		return 0;
	}
	@Override
	public int getValueEnd() {
		// TODO Auto-generated method stub
		return 0;
	}
}
