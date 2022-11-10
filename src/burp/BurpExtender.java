package burp;

import java.awt.Component;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.PrintWriter;
import java.net.URLDecoder;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import javax.swing.JMenuItem;
import javax.swing.SortOrder;
import javax.swing.SwingUtilities;
import javax.swing.table.DefaultTableModel;

import custom.CGUI;


public class BurpExtender implements IBurpExtender, IHttpListener, ITab, IContextMenuFactory
{
	private IBurpExtenderCallbacks callbacks;
	private IExtensionHelpers helpers;
	private PrintWriter stdout;//现在这里定义变量，再在registerExtenderCallbacks函数中实例化，如果都在函数中就只是局部变量，不能在这实例化，因为要用到其他参数。
	public String extenderName = "Resign v2.3 by bit4";


	public String secretKey = null;
	public int sortedColumn;
	public SortOrder sortedMethod;
	public String howDealKey = ""; //sameAsPara  or appendToEnd
	String signPara = null; //the key name of sign parameter
	private String signParaType;
	private CGUI GUI;
	private IHttpRequestResponse currentMessage;
	static final byte PARAM_Header = 7;



	// implement IBurpExtender
	@Override
	public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks)
	{//当加载插件的时候，会调用下面的方法。
		stdout = new PrintWriter(callbacks.getStdout(), true);
		//PrintWriter stdout = new PrintWriter(callbacks.getStdout(), true); 这种写法是定义变量和实例化，这里的变量就是新的变量而不是之前class中的全局变量了。
		stdout.println(extenderName+"    https://github.com/bit4woo\r\n");
		//System.out.println("test"); 不会输出到burp的
		this.callbacks = callbacks;
		helpers = callbacks.getHelpers();
		callbacks.setExtensionName(extenderName); //插件名称
		callbacks.registerHttpListener(this); //如果没有注册，下面的processHttpMessage方法是不会生效的。处理请求和响应包的插件，这个应该是必要的
		callbacks.registerContextMenuFactory(this);
		GUI = new CGUI();
		addMenuTab();
	}

	@Override
	public void processHttpMessage(int toolFlag,boolean messageIsRequest,IHttpRequestResponse messageInfo)
	{
		if (toolFlag == (toolFlag&GUI.checkEnabledFor())){ //不同的toolflag代表了不同的burp组件 https://portswigger.net/burp/extender/api/constant-values.html#burp.IBurpExtenderCallbacks
			if (messageIsRequest){ //对请求包进行处理
				stdout.println("Origin Request:");
				stdout.println(new String(messageInfo.getRequest()));
				stdout.println("\r\n");
				HelperPlus getter = new HelperPlus(helpers);
				String host = getter.getHost(messageInfo);
				IRequestInfo analyzeRequest = helpers.analyzeRequest(messageInfo); //对消息体进行解析
				signPara =GUI.getSignPara();
				byte getSignParaType = getSignParaType(messageInfo);

				//*******************recalculate sign**************************//
				if (host.equals(GUI.getHostFromUI()) && getSignParaType !=-1){//检查图形面板上的各种参数，都齐备了才进行。
					byte[] new_Request = messageInfo.getRequest();
					String str = GUI.combineString(getUpdatedParaBaseOnTable(analyzeRequest),GUI.getOnlyValueConfig(),GUI.getParaConnector());
					//stdout.println("Combined String:"+str);
					String newSign = GUI.calcSign(str);
					//stdout.println("New Sign:"+newSign); //输出到extender的UI窗口，可以让使用者有一些判断
					//更新参数
					//newSign = newSign.toUpperCase();

					if(getSignParaType == IParameter.PARAM_JSON) {
						int bodyOffset = analyzeRequest.getBodyOffset();
						List<String> headers = analyzeRequest.getHeaders();

						byte[] byte_Request = messageInfo.getRequest();//当需要byte[]和string格式的请求包时用这个方法！
						String request = new String(byte_Request); //byte[] to String

						String body = request.substring(bodyOffset);
						String oldchar = getSignParaValue(analyzeRequest);
						callbacks.printOutput(oldchar);
						String newBody = body.replace(getSignParaValue(analyzeRequest), newSign);

						byte[] bodyByte = newBody.getBytes();
						new_Request = helpers.buildHttpMessage(headers, bodyByte); //关键方法
						messageInfo.setRequest(new_Request);//设置最终新的请求包
					}else if(getSignParaType == PARAM_Header) {
						List<String> headers = getter.getHeaderList(true,messageInfo);
						byte[] body = getter.getBody(true, messageInfo);

						for (String header:headers) {
							if (header.startsWith(signPara+":")) {
								headers.remove(header);
								headers.add(signPara+": "+newSign);
								break;
							}
						}

						new_Request = helpers.buildHttpMessage(headers, body); //关键方法
						messageInfo.setRequest(new_Request);//设置最终新的请求包
					}else {
						IParameter newPara = helpers.buildParameter(signPara, newSign, getSignParaType); //构造新的参数,如果参数是PARAM_JSON类型，这个方法是不适用的
						new_Request = helpers.updateParameter(new_Request, newPara); //构造新的请求包，这里是方法一updateParameter
						messageInfo.setRequest(new_Request);//设置最终新的请求包
					}

					stdout.println("Changed Request:");
					stdout.println(new String(messageInfo.getRequest()));
					stdout.print("\r\n");
					//to verify the updated result
					//	    			for (IParameter para : helpers.analyzeRequest(messageInfo).getParameters()){
					//	    				stdout.println(para.getValue());
					//	    			}

				}
			}
		}  		
	}

	//根据GUI中的有序参数列表，更新当前请求的参数列表。
	public Map<String, String> getUpdatedParaBaseOnTable(IRequestInfo analyzeRequest){
		List<IParameter> paras = analyzeRequest.getParameters();//当body是json格式的时候，这个方法也可以正常获取到键值对，牛掰。但是PARAM_JSON等格式不能通过updateParameter方法来更新。
		Map<String,String> paraMap = GUI.getParaFromTable();
		for (IParameter para:paras){
			if (paraMap.keySet().contains(para.getName())){
				if (paraMap.get(para.getName()).contains("<timestamp>")){
					paraMap.put(para.getName(), paraMap.get(para.getName()).replace("<timestamp>", Long.toString(System.currentTimeMillis())));
				}else {
					paraMap.put(para.getName(), para.getValue());
					//stdout.println(para.getName()+":"+para.getValue());
				}
			}
		}
		return paraMap ;
	}

	public Map<String, String> getPara(IRequestInfo analyzeRequest){
		List<IParameter> paras = analyzeRequest.getParameters();//当body是json格式的时候，这个方法也可以正常获取到键值对，牛掰。但是PARAM_JSON等格式不能通过updateParameter方法来更新。
		Map<String,String> paraMap = new HashMap<String,String>();
		for (IParameter para:paras){
			paraMap.put(para.getName(), para.getValue());
		}
		return paraMap ;
	}

	public Map<String, String> getParaAndHeader(IHttpRequestResponse messageInfo){

		Getter getter = new Getter(helpers);

		List<IParameter> paras = getter.getParas(messageInfo);
		HashMap<String,String> paraMap = new HashMap<String,String>();
		for (IParameter para:paras){
			paraMap.put(para.getName(), para.getValue());
		}
		LinkedHashMap<String, String> headers = getter.getHeaderMap(true,messageInfo);
		paraMap.putAll(headers);
		return paraMap ;
	}

	public byte getSignParaType(IHttpRequestResponse messageInfo){
		Getter getter = new Getter(helpers);

		List<IParameter> paras = getter.getParas(messageInfo);
		byte signParaType = -1;
		for (IParameter para:paras){
			if (para.getName().equals(signPara)){
				signParaType = para.getType();
				return signParaType;
			}
		}

		LinkedHashMap<String, String> headers = getter.getHeaderMap(true,messageInfo);
		for (String header:headers.keySet()){
			if (header.equals(signPara)){
				return PARAM_Header;
			}
		}
		return signParaType;
	}

	public String getSignParaValue(IRequestInfo analyzeRequest){
		List<IParameter> paras = analyzeRequest.getParameters();//当body是json格式的时候，这个方法也可以正常获取到键值对，牛掰。但是PARAM_JSON等格式不能通过updateParameter方法来更新。
		String signParaType = null;
		for (IParameter para:paras){
			if (para.getName().equals(signPara)){
				signParaType = para.getValue();

			}
		}
		return signParaType;
	}



	//以下是各种burp必须的方法 --start
	public void addMenuTab()
	{
		SwingUtilities.invokeLater(new Runnable()
		{
			public void run()
			{
				BurpExtender.this.callbacks.addSuiteTab(BurpExtender.this); 
				//这里的BurpExtender.this实质是指ITab对象，也就是getUiComponent()中的contentPane.这个参数由CGUI()函数初始化。
				//如果这里报java.lang.NullPointerException: Component cannot be null 错误，需要排查contentPane的初始化是否正确。
			}
		});
	}


	//ITab必须实现的两个方法
	@Override
	public String getTabCaption() {
		return ("ReSign");
	}
	@Override
	public Component getUiComponent() {
		return GUI.getContentPane();
	}
	//ITab必须实现的两个方法



	//IContextMenuFactory 必须实现的方法
	@Override
	public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation)
	{ //需要在前面注册！！callbacks.registerContextMenuFactory(this);
		IHttpRequestResponse[] messages = invocation.getSelectedMessages();
		List<JMenuItem> list = new ArrayList<JMenuItem>();
		if((messages != null) && (messages.length > 0))
		{
			//this.callbacks.printOutput("Messages in array: " + messages.length);

			currentMessage = messages[0];
			JMenuItem menuItem = new JMenuItem("Send to ReSign");
			menuItem.addActionListener(new ActionListener()
			{
				public void actionPerformed(ActionEvent e)
				{
					try
					{
						GUI.textFieldDomain.setText(currentMessage.getHttpService().getHost());

						DefaultTableModel tableModel = (DefaultTableModel) GUI.table.getModel();
						tableModel.setRowCount(0);//为了清空之前的数据

						Map<String,String> paraMap = getParaAndHeader(currentMessage);
						for(String key:paraMap.keySet()){
							tableModel.addRow(new Object[]{URLDecoder.decode(key),URLDecoder.decode(paraMap.get(key))});
						}
					}
					catch (Exception e1)
					{
						BurpExtender.this.callbacks.printError(e1.getMessage());
					}
				}
			});
			list.add(menuItem);
		}
		return list;
	}
	//各种burp必须的方法 --end

}