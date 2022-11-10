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
	public static IExtensionHelpers helpers;
	private PrintWriter stdout;//现在这里定义变量，再在registerExtenderCallbacks函数中实例化，如果都在函数中就只是局部变量，不能在这实例化，因为要用到其他参数。
	public String extenderName = "Resign v2.3 by bit4woo";


	public String secretKey = null;
	public int sortedColumn;
	public SortOrder sortedMethod;
	public String howDealKey = ""; //sameAsPara  or appendToEnd

	private CGUI GUI;
	public static IHttpRequestResponse currentMessage;
	public static List<IParameter> paras;
	public static IParameter signPara;


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
				getSignPara();

				//*******************recalculate sign**************************//
				if (host.equals(GUI.getHostFromUI()) && signPara.getType() !=-1){//检查图形面板上的各种参数，都齐备了才进行。
					String timeStamp = Long.toString(System.currentTimeMillis());
					
					String str = GUI.combineString(GUI.getParaMapFromTable(),GUI.getOnlyValueConfig(),GUI.getParaConnector());
					str = str.replace("<timestamp>", timeStamp);
					String newSign = GUI.calcSign(str);
					
					//更新参数
					IParameter newSignPara = new Parameter(signPara.getName(),newSign,signPara.getType());
					updateMessage(true,messageInfo,newSignPara);
					
					IParameter timePara = GUI.getParaThatUseTimeStamp();
					
					IParameter newTimePara = new Parameter(timePara.getName(),timeStamp,timePara.getType());
					updateMessage(true,messageInfo,newTimePara);

					stdout.println("Changed Request:");
					stdout.println(new String(messageInfo.getRequest()));
					stdout.print("\r\n");
				}
			}
		}  		
	}
	
	/**
	 * 更新数据包。要替换的数据包可能时header头--自行实现的
	 * 
	 */
	public void updateMessage(boolean messageIsRequest,IHttpRequestResponse messageInfo,IParameter para) {
		HelperPlus getter = new HelperPlus(helpers);
		
		if(para.getType() == IParameter.PARAM_JSON) {
			List<String> headers = getter.getHeaderList(messageIsRequest,messageInfo);

			byte[] body = HelperPlus.getBody(messageIsRequest, messageInfo);
			
			String oldchar = getter.getParameterByKey(messageInfo, para.getName()).getValue();
			String newBody = new String(body).replace(oldchar, para.getValue());

			byte[] bodyByte = newBody.getBytes();
			byte[] new_Request = helpers.buildHttpMessage(headers, bodyByte); //关键方法
			messageInfo.setRequest(new_Request);//设置最终新的请求包
		}else if(para.getType() == Parameter.PARAM_Header) {
			List<String> headers = getter.getHeaderList(true,messageInfo);
			byte[] body = HelperPlus.getBody(true, messageInfo);

			for (String header:headers) {
				if (header.startsWith(para.getName()+":")) {
					headers.remove(header);
					headers.add(para.getName()+": "+para.getValue());
					break;
				}
			}

			byte[] new_Request = helpers.buildHttpMessage(headers, body); //关键方法
			messageInfo.setRequest(new_Request);//设置最终新的请求包
		}else {
			byte[] new_Request = helpers.updateParameter(messageInfo.getRequest(), para); //构造新的请求包，这里是方法一updateParameter
			messageInfo.setRequest(new_Request);//设置最终新的请求包
		}
	}
	
	public void getSignPara(){
		String signParaName = GUI.textFieldSign.getText();
		List<IParameter> paras = getParasAndHeaders(currentMessage);
		for(IParameter para:paras){
			if (para.getName().equals(signParaName)) {
				signPara = para;
			}
		}
	}


	/**
	 * 返回各种可能用于签名的参数、包含header。
	 * @param messageInfo
	 * @return
	 */
	public List<IParameter> getParasAndHeaders(IHttpRequestResponse messageInfo){

		Getter getter = new Getter(BurpExtender.helpers);

		List<IParameter> paras = getter.getParas(messageInfo);
		LinkedHashMap<String, String> headers = getter.getHeaderMap(true,messageInfo);
		for (String key:headers.keySet()) {
			Parameter para = new Parameter(key,headers.get(key),Parameter.PARAM_Header);
			paras.add(para);
		}
		return paras;
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

						List<IParameter> paras = getParasAndHeaders(currentMessage);
						for(IParameter para:paras){
							tableModel.addRow(new Object[]{URLDecoder.decode(para.getName()),URLDecoder.decode(para.getValue()),para.getType()});
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