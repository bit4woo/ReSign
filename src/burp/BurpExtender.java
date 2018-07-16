package burp;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import java.awt.BorderLayout;
import java.awt.Color;

import javax.swing.JCheckBox;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.border.EmptyBorder;
import javax.swing.border.EtchedBorder;
import javax.swing.JLabel;
import javax.swing.JMenuItem;

import java.awt.FlowLayout;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import javax.swing.SwingConstants;
import javax.swing.SwingUtilities;
import javax.swing.JTextField;
import javax.swing.RowSorter;
import javax.swing.SortOrder;
import javax.swing.JTable;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableModel;
import javax.swing.table.TableRowSorter;
import java.awt.GridLayout;

import javax.swing.ButtonGroup;
import javax.swing.JButton;
import javax.swing.JTextArea;
import java.awt.event.ActionListener;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.awt.event.ActionEvent;


import java.awt.Component;
import java.awt.Cursor;
import java.awt.Desktop;
import java.io.PrintWriter;
import java.net.URI;
import java.net.URLDecoder;
import burp.IParameter;
import custom.CMD5;
import custom.CSHA1;



public class BurpExtender implements IBurpExtender, IHttpListener, ITab, IContextMenuFactory
{
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private PrintWriter stdout;//现在这里定义变量，再在registerExtenderCallbacks函数中实例化，如果都在函数中就只是局部变量，不能在这实例化，因为要用到其他参数。
	public JCheckBox chckbxProxy;
	public JCheckBox chckbxScanner;
	public JCheckBox chckbxIntruder;
	public JCheckBox chckbxRepeater;
	public static JTextField textFieldDomain;
	public static JTable table;
	public JTextField textFieldSecretKey;
	public JCheckBox chckbxAppendToEnd;
	public JCheckBox chckbxSameAsPara;
	public JTextField textFieldConnector;
	public JTextArea textAreaFinalString;
	public JCheckBox chckbxMD5;
	public JCheckBox chckbxSHA1;
	public JCheckBox chckbxNewCheckBox_3;
	public JTextArea textAreaSign;
	public JPanel contentPane;
	private final ButtonGroup buttonGroup = new ButtonGroup();
	private final ButtonGroup buttonGroup1 = new ButtonGroup();
	public String extenderName = "Resign v2.3 by bit4";
	private JTextField textFieldParaConnector;
	public JLabel lblOrderMethod;
	
	
	
	public String secretKey = null;
	public int sortedColumn;
	public SortOrder sortedMethod;
	public String howDealKey = ""; //sameAsPara  or appendToEnd
	String signPara = null; //the key name of sign parameter
	private JTextField textFieldSign;
	private JCheckBox chckbxOnlyUseValue;
	
    
	
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
        addMenuTab();
    }

    @Override
    public void processHttpMessage(int toolFlag,boolean messageIsRequest,IHttpRequestResponse messageInfo)
    {
    	if (toolFlag == (toolFlag&checkEnabledFor())){ //不同的toolflag代表了不同的burp组件 https://portswigger.net/burp/extender/api/constant-values.html#burp.IBurpExtenderCallbacks
    		if (messageIsRequest){ //对请求包进行处理
    			stdout.println("Origin Request:");
    			stdout.println(new String(messageInfo.getRequest()));
    			stdout.println("\r\n");
    			IRequestInfo analyzeRequest = helpers.analyzeRequest(messageInfo); //对消息体进行解析 
                byte getSignParaType = getSignParaType(analyzeRequest);
                
                //*******************recalculate sign**************************//
				if (getHost(analyzeRequest).equals(getHostFromUI()) && getSignParaType !=-1){//检查图形面板上的各种参数，都齐备了才进行。
	    			byte[] new_Request = messageInfo.getRequest();
	    			String str = combineString(getUpdatedParaBaseOnTable(analyzeRequest),getOnlyValueConfig(),getParaConnector());
	    			//stdout.println("Combined String:"+str);
					String newSign = calcSign(str);
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

    
	public void CGUI() {
		
		contentPane = new JPanel();
		contentPane.setBorder(new EmptyBorder(5, 5, 5, 5));
		contentPane.setLayout(new BorderLayout(0, 0));

		
		JPanel enableConfigPanel = new JPanel();
		enableConfigPanel.setBorder(new EtchedBorder(EtchedBorder.LOWERED, null, null));
		FlowLayout flowLayout = (FlowLayout) enableConfigPanel.getLayout();
		flowLayout.setAlignment(FlowLayout.LEFT);
		contentPane.add(enableConfigPanel, BorderLayout.NORTH);
		
		
		JPanel panel_3 = new JPanel();
		panel_3.setBorder(null);
		enableConfigPanel.add(panel_3);
		panel_3.setLayout(new FlowLayout(FlowLayout.CENTER, 5, 5));
		
		JLabel enableFor = new JLabel("Enable For :");
		panel_3.add(enableFor);
		
		chckbxProxy = new JCheckBox("Proxy");
		panel_3.add(chckbxProxy);
		
		chckbxScanner = new JCheckBox("Scanner");
		panel_3.add(chckbxScanner);
		
		chckbxIntruder = new JCheckBox("Intruder");
		panel_3.add(chckbxIntruder);
		
		chckbxRepeater = new JCheckBox("Repeater");
		chckbxRepeater.setSelected(true);
		panel_3.add(chckbxRepeater);
		
		JPanel panel_1 = new JPanel();
		panel_1.setBorder(new EtchedBorder(EtchedBorder.LOWERED, null, null));
		contentPane.add(panel_1, BorderLayout.SOUTH);
		panel_1.setLayout(new FlowLayout(FlowLayout.LEFT, 5, 5));
		
		JLabel lblNewLabel = new JLabel(extenderName+"    https://github.com/bit4woo");
		lblNewLabel.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseClicked(MouseEvent e) {
				try {
					URI uri = new URI("https://github.com/bit4woo");
					Desktop desktop = Desktop.getDesktop();
					if(Desktop.isDesktopSupported()&&desktop.isSupported(Desktop.Action.BROWSE)){
						desktop.browse(uri);
					}
				} catch (Exception e2) {
					// TODO: handle exception
					BurpExtender.this.callbacks.printError(e2.getMessage());
				}
				
			}
			@Override
			public void mouseEntered(MouseEvent e) {
				lblNewLabel.setForeground(Color.BLUE);
			}
			@Override
			public void mouseExited(MouseEvent e) {
				lblNewLabel.setForeground(Color.BLACK);
			}
		});
		lblNewLabel.setHorizontalAlignment(SwingConstants.LEFT);
		panel_1.add(lblNewLabel);
		
		JPanel panel = new JPanel();
		panel.setBorder(new EtchedBorder(EtchedBorder.LOWERED, null, null));
		contentPane.add(panel, BorderLayout.CENTER);
		panel.setLayout(new BorderLayout(0, 0));
		
		JPanel panel_5 = new JPanel();
		panel.add(panel_5, BorderLayout.NORTH);
		panel_5.setLayout(new GridLayout(0, 1, 0, 0));
		
		JLabel lblURL = new JLabel("Domain:");
		panel_5.add(lblURL);
		
		textFieldDomain = new JTextField();
		panel_5.add(textFieldDomain);
		textFieldDomain.setColumns(20);
		
		JLabel lblParas = new JLabel("[1] Parameters:(Click Table Header To Sort Or Move Up And Down To Custom)");
		panel_5.add(lblParas);
		
		JScrollPane panel_6 = new JScrollPane();
		panel_6.setBorder(new EtchedBorder(EtchedBorder.LOWERED, null, null));
		panel.add(panel_6, BorderLayout.CENTER);
		
		table = new JTable();
		table.getTableHeader().addMouseListener(new MouseAdapter() {
			@Override
			public void mouseClicked(MouseEvent e) {
				try {
					sortedColumn = table.getRowSorter().getSortKeys().get(0).getColumn();
					//System.out.println(sortedColumn);
					sortedMethod = table.getRowSorter().getSortKeys().get(0).getSortOrder();
					System.out.println(sortedMethod); //ASCENDING   DESCENDING
				} catch (Exception e1) {
					sortedColumn = -1;
					sortedMethod = null;
					BurpExtender.this.callbacks.printError(e1.getMessage());
				}
//				System.out.println(sortedColumn);
//				System.out.println(sortedMethod);
				lblOrderMethod.setText(table.getColumnName(sortedColumn)+" "+sortedMethod);
			}
		});
		table.setColumnSelectionAllowed(true);
		table.setCellSelectionEnabled(true);
		table.setSurrendersFocusOnKeystroke(true);
		table.setFillsViewportHeight(true);
		table.setCursor(Cursor.getPredefinedCursor(Cursor.TEXT_CURSOR));
		DefaultTableModel tableModel = new DefaultTableModel(
				new Object[][] {
					//{null, null},
				},
				new String[] {
					"Key", "Value"
				});
		RowSorter<TableModel> sorter = new TableRowSorter<TableModel>(tableModel);
		table.setRowSorter(sorter);
		panel_6.setViewportView(table);
		table.setModel(tableModel);
		
		JPanel panel_7 = new JPanel();
		panel.add(panel_7, BorderLayout.EAST);
		GridBagLayout gbl_panel_7 = new GridBagLayout();
		gbl_panel_7.columnWidths = new int[]{93, 0};
		gbl_panel_7.rowHeights = new int[]{23, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
		gbl_panel_7.columnWeights = new double[]{1.0, Double.MIN_VALUE};
		gbl_panel_7.rowWeights = new double[]{0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, Double.MIN_VALUE};
		panel_7.setLayout(gbl_panel_7);
		
		
		JButton btnMarkAsSign = new JButton("Mark As Sign Para");
		btnMarkAsSign.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				if (table.getSelectedRow() != -1){
					signPara = table.getValueAt(table.getSelectedRow(), 0).toString();
					textFieldSign.setText(signPara);
				}
			}
		});
		
		
		JButton btnMoveDown = new JButton("Move Down");
		btnMoveDown.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				if (table.getSelectedRow() != -1 && table.getSelectedRow()+1 <= table.getRowCount()-1){
					try{
						int row = table.getSelectedRow();
						String xkey = table.getValueAt(row, 0).toString();
						String xvalue = table.getValueAt(row, 1).toString();
						
						String tmpkey = table.getValueAt(row+1, 0).toString();
						String tmpvalue = table.getValueAt(row+1, 1).toString();
						
						//do exchange 
						tableModel.setValueAt(tmpkey, row, 0);
						tableModel.setValueAt(tmpvalue, row, 1);
						
						tableModel.setValueAt(xkey, row+1, 0);
						tableModel.setValueAt(xvalue, row+1, 1);
						
						table.setRowSelectionInterval(row+1, row+1);//set the line selected

						lblOrderMethod.setText("Custom Order");
					}catch(Exception e1){
						BurpExtender.this.callbacks.printError(e1.getMessage());
						
					}
					
					
				}
			}
		});
		
		JButton btnMoveUp = new JButton("Move Up");
		btnMoveUp.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				if (table.getSelectedRow() != -1 && table.getSelectedRow()-1 >=0){
					try {
						int row = table.getSelectedRow();
						String xkey = table.getValueAt(row, 0).toString();
						String xvalue = table.getValueAt(row, 1).toString();
						
						String tmpkey = table.getValueAt(row-1, 0).toString();
						String tmpvalue = table.getValueAt(row-1, 1).toString();
						
						//do exchange 
						tableModel.setValueAt(tmpkey, row, 0);
						tableModel.setValueAt(tmpvalue, row, 1);
						
						tableModel.setValueAt(xkey, row-1, 0);
						tableModel.setValueAt(xvalue, row-1, 1);
						
						table.setRowSelectionInterval(row-1, row-1);
						
						lblOrderMethod.setText("Custom Order");
					} catch (Exception e2) {
						// TODO: handle exception
						BurpExtender.this.callbacks.printError(e2.getMessage());
					}

				}
			}
		});
		
		JButton btnAdd = new JButton("Add");
		btnAdd.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				DefaultTableModel model = (DefaultTableModel) table.getModel();
				model.addRow(new Object[]{"key","value"});
				lblOrderMethod.setText("Custom Order");
			}
		});
		
		JButton btnNewButton = new JButton("Remove");
		btnNewButton.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				int[] rowindexs = table.getSelectedRows();
				for (int i=0; i < rowindexs.length; i++){
					rowindexs[i] = table.convertRowIndexToModel(rowindexs[i]);//转换为Model的索引，否则排序后索引不对应。
				}
				Arrays.sort(rowindexs);
				
				DefaultTableModel tableModel = (DefaultTableModel) table.getModel();
				for(int i=rowindexs.length-1;i>=0;i--){
					tableModel.removeRow(rowindexs[i]);
				}
				lblOrderMethod.setText("Custom Order");
			}
		});
		
		
		lblOrderMethod = new JLabel("Custom Order");
		GridBagConstraints gbc_lblOrderMethod = new GridBagConstraints();
		gbc_lblOrderMethod.insets = new Insets(0, 0, 5, 0);
		gbc_lblOrderMethod.gridx = 0;
		gbc_lblOrderMethod.gridy = 0;
		panel_7.add(lblOrderMethod, gbc_lblOrderMethod);
		GridBagConstraints gbc_btnNewButton = new GridBagConstraints();
		gbc_btnNewButton.insets = new Insets(0, 0, 5, 0);
		gbc_btnNewButton.gridx = 0;
		gbc_btnNewButton.gridy = 1;
		panel_7.add(btnNewButton, gbc_btnNewButton);
		GridBagConstraints gbc_btnAdd = new GridBagConstraints();
		gbc_btnAdd.insets = new Insets(0, 0, 5, 0);
		gbc_btnAdd.gridx = 0;
		gbc_btnAdd.gridy = 2;
		panel_7.add(btnAdd, gbc_btnAdd);
		GridBagConstraints gbc_btnMoveUp = new GridBagConstraints();
		gbc_btnMoveUp.insets = new Insets(0, 0, 5, 0);
		gbc_btnMoveUp.gridx = 0;
		gbc_btnMoveUp.gridy = 3;
		panel_7.add(btnMoveUp, gbc_btnMoveUp);
		GridBagConstraints gbc_btnMoveDown = new GridBagConstraints();
		gbc_btnMoveDown.insets = new Insets(0, 0, 5, 0);
		gbc_btnMoveDown.gridx = 0;
		gbc_btnMoveDown.gridy = 4;
		panel_7.add(btnMoveDown, gbc_btnMoveDown);
		GridBagConstraints gbc_btnMarkAsSign = new GridBagConstraints();
		gbc_btnMarkAsSign.insets = new Insets(0, 0, 5, 0);
		gbc_btnMarkAsSign.gridx = 0;
		gbc_btnMarkAsSign.gridy = 6;
		panel_7.add(btnMarkAsSign, gbc_btnMarkAsSign);
		
		textFieldSign = new JTextField();
		GridBagConstraints gbc_textFieldSign = new GridBagConstraints();
		gbc_textFieldSign.insets = new Insets(0, 0, 5, 0);
		gbc_textFieldSign.fill = GridBagConstraints.HORIZONTAL;
		gbc_textFieldSign.gridx = 0;
		gbc_textFieldSign.gridy = 7;
		panel_7.add(textFieldSign, gbc_textFieldSign);
		textFieldSign.setColumns(10);
		
		JButton button = new JButton("Show Final String");
		button.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				//System.out.println(getOnlyValueConfig());
				//System.out.println(getSignPara());
				if (getSignPara().equals("")){
					textAreaFinalString.setText("error! sign parameter must be specified!");
				}else{
					String str = combineString(getParaFromTable(),getOnlyValueConfig(),getParaConnector());
					if (str.contains("<timestamp>")){
						str = str.replace("<timestamp>", Long.toString(System.currentTimeMillis()));//需要重新赋值，否则不会被更新
					}
					textAreaFinalString.setText(str);
				}
			}
		});
		GridBagConstraints gbc_button = new GridBagConstraints();
		gbc_button.insets = new Insets(0, 0, 5, 0);
		gbc_button.gridx = 0;
		gbc_button.gridy = 9;
		panel_7.add(button, gbc_button);
		
		
		
		JPanel panel_8 = new JPanel();
		panel_8.setBorder(new EtchedBorder(EtchedBorder.LOWERED, null, null));
		panel.add(panel_8, BorderLayout.SOUTH);
		panel_8.setLayout(new GridLayout(0, 1, 0, 0));
		
		JLabel lblSecretKey = new JLabel("[2] Secret Key :");
		panel_8.add(lblSecretKey);
		
		textFieldSecretKey = new JTextField();
		panel_8.add(textFieldSecretKey);
		textFieldSecretKey.setHorizontalAlignment(SwingConstants.LEFT);
		textFieldSecretKey.setColumns(50);
		
		
		chckbxSameAsPara = new JCheckBox("Add secret key as a parameter. eg. key=secretkey");
		panel_8.add(chckbxSameAsPara);
		chckbxSameAsPara.setSelected(true);
		buttonGroup.add(chckbxSameAsPara);
		
		chckbxAppendToEnd = new JCheckBox("Append to the end of sorted Parameters. eg. &key=secretkey");
		panel_8.add(chckbxAppendToEnd);
		buttonGroup.add(chckbxAppendToEnd);
		
		JLabel lblNewLabel_1 = new JLabel("[3] How To Combine\uFF1A ");
		panel_8.add(lblNewLabel_1);
		
		chckbxOnlyUseValue = new JCheckBox("Only Use Value");
		panel_8.add(chckbxOnlyUseValue);
		
		JLabel lblConnecStringBetween = new JLabel("connection string between each parameter");
		panel_8.add(lblConnecStringBetween);
		
		textFieldParaConnector = new JTextField();
		textFieldParaConnector.setText("&");
		panel_8.add(textFieldParaConnector);
		textFieldParaConnector.setColumns(50);
		
		
		JPanel panel_2 = new JPanel();
		panel_2.setBorder(new EtchedBorder(EtchedBorder.LOWERED, null, null));
		contentPane.add(panel_2, BorderLayout.EAST);
		panel_2.setLayout(new BorderLayout(0, 0));
		
		textAreaFinalString = new JTextArea();
		textAreaFinalString.setLineWrap(true);
		textAreaFinalString.setColumns(20);
		textAreaFinalString.setRows(20);
		panel_2.add(textAreaFinalString, BorderLayout.WEST);
		
		textAreaSign = new JTextArea();
		textAreaSign.setLineWrap(true);
		textAreaSign.setColumns(20);
		panel_2.add(textAreaSign, BorderLayout.EAST);
		
		JPanel panel_10 = new JPanel();
		panel_2.add(panel_10, BorderLayout.NORTH);
		GridBagLayout gbl_panel_10 = new GridBagLayout();
		gbl_panel_10.columnWidths = new int[]{108, 43, 109, 0};
		gbl_panel_10.rowHeights = new int[]{23, 0, 0, 0, 0};
		gbl_panel_10.columnWeights = new double[]{0.0, 0.0, 0.0, Double.MIN_VALUE};
		gbl_panel_10.rowWeights = new double[]{0.0, 0.0, 0.0, 0.0, Double.MIN_VALUE};
		panel_10.setLayout(gbl_panel_10);
		
		JLabel lblNewLabel_2 = new JLabel("Chose Sign Method:");
		GridBagConstraints gbc_lblNewLabel_2 = new GridBagConstraints();
		gbc_lblNewLabel_2.anchor = GridBagConstraints.WEST;
		gbc_lblNewLabel_2.insets = new Insets(0, 0, 5, 5);
		gbc_lblNewLabel_2.gridx = 0;
		gbc_lblNewLabel_2.gridy = 0;
		panel_10.add(lblNewLabel_2, gbc_lblNewLabel_2);
		
		chckbxMD5 = new JCheckBox("MD5");
		chckbxMD5.setSelected(true);
		GridBagConstraints gbc_chckbxMD5 = new GridBagConstraints();
		gbc_chckbxMD5.anchor = GridBagConstraints.NORTHWEST;
		gbc_chckbxMD5.insets = new Insets(0, 0, 5, 5);
		gbc_chckbxMD5.gridx = 0;
		gbc_chckbxMD5.gridy = 1;
		panel_10.add(chckbxMD5, gbc_chckbxMD5);
		buttonGroup1.add(chckbxMD5);
		
		chckbxSHA1 = new JCheckBox("SHA1");
		chckbxSHA1.setSelected(true);
		GridBagConstraints gbc_chckbxSHA1 = new GridBagConstraints();
		gbc_chckbxSHA1.insets = new Insets(0, 0, 5, 5);
		gbc_chckbxSHA1.gridx = 1;
		gbc_chckbxSHA1.gridy = 1;
		panel_10.add(chckbxSHA1, gbc_chckbxSHA1);
		buttonGroup1.add(chckbxSHA1);
		
		chckbxNewCheckBox_3 = new JCheckBox("To be Continue");
		chckbxNewCheckBox_3.setSelected(true);
		chckbxNewCheckBox_3.setEnabled(false);
		GridBagConstraints gbc_chckbxNewCheckBox_3 = new GridBagConstraints();
		gbc_chckbxNewCheckBox_3.insets = new Insets(0, 0, 5, 0);
		gbc_chckbxNewCheckBox_3.anchor = GridBagConstraints.NORTHWEST;
		gbc_chckbxNewCheckBox_3.gridx = 2;
		gbc_chckbxNewCheckBox_3.gridy = 1;
		panel_10.add(chckbxNewCheckBox_3, gbc_chckbxNewCheckBox_3);
		
		JPanel panel_11 = new JPanel();
		panel_2.add(panel_11, BorderLayout.CENTER);
		
		JButton btnSign = new JButton("Sign");
		btnSign.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				textAreaSign.setText(calcSign(textAreaFinalString.getText()));
			}
		});
		panel_11.add(btnSign);
	}
	
	
    
    
    //各种从图形面板或者从数据包获取参数，获取配置的函数。--start
    
	public int checkEnabledFor(){
		//get values that should enable this extender for which Component.
		int status = 0;
		if (chckbxIntruder.isSelected()){
			status += 32;
		}
		if(chckbxProxy.isSelected()){
			status += 4;
		}
		if(chckbxRepeater.isSelected()){
			status += 64;
		}
		if(chckbxScanner.isSelected()){
			status += 16;
		}
		return status;
	}
	
	
	public void getSecKeyConfig() {
		if (secretKey != null && secretKey != ""){
			secretKey = textFieldSecretKey.getText();
		}
		if(chckbxAppendToEnd.isSelected()){
			howDealKey = "appendToEnd";
		}
		else if (chckbxSameAsPara.isSelected()) {
			howDealKey = "sameAsPara";
		}
	}
	
	public boolean getOnlyValueConfig() {
		if(chckbxOnlyUseValue.isSelected()){
			return true;
		}else{
			return false;
		}
	}
	public String getParaConnector() {
		return textFieldParaConnector.getText();
	}
	
	public String getSignPara(){
		return textFieldSign.getText();
	}
	
	public String getSignAlgorithm() {
		if (chckbxMD5.isSelected()){
			return "MD5";
		}else if (chckbxSHA1.isSelected()) {
			return "SHA1";
		}else {
			return "null";
		}
	}
	
	
	
	//两个核心方法：1是拼接字符串，2是计算出sign
	public String calcSign(String str){
		String sign = "Sign Error";
		//System.out.print(getSignAlgorithm());
		if (getSignAlgorithm().equals("MD5")){
			sign = CMD5.GetMD5Code(str);
		}else if (getSignAlgorithm().equals("SHA1")) {
			sign = CSHA1.SHA1(str);
		}
		return sign;
	}

	
	//两个核心方法：1是拼接字符串，2是计算出sign
	public String combineString(Map<String, String> paraMap, boolean onlyValue, String paraConnector) {
		getSecKeyConfig();
		
		String finalString = "";
		
		
		if (howDealKey.equals("sameAsPara")){
			secretKey = textFieldSecretKey.getText();
			if(secretKey.contains("=") & secretKey.split("=").length==2){
				paraMap.put(secretKey.split("=")[0], secretKey.split("=")[1]);
			}
		}
		
		
		if (lblOrderMethod.getText().equals("Custom Order")){//sortedColumn == -1 || 
			for(Map.Entry<String,String>para:paraMap.entrySet()){
				if (!finalString.equals("")){
					finalString += paraConnector;
				}
				if (onlyValue){
					finalString += para.getValue();
				}else {
					finalString += para;
				}
			}
		}else if(sortedColumn == 0) {
			if (sortedMethod.toString() == "ASCENDING"){
				finalString = custom.CMapSort.combineMapEntry(custom.CMapSort.sortMapByKey(paraMap,"ASCENDING"), onlyValue, paraConnector);
			}else if (sortedMethod.toString() == "DESCENDING") {
				finalString = custom.CMapSort.combineMapEntry(custom.CMapSort.sortMapByKey(paraMap,"DESCENDING"), onlyValue, paraConnector);
			}
		}
		else if (sortedColumn == 1) {
			if (sortedMethod.toString() == "ASCENDING"){
				finalString = custom.CMapSort.combineMapEntry(custom.CMapSort.sortMapByValue(paraMap,"ASCENDING"), onlyValue, paraConnector);
			}else if (sortedMethod.toString() == "DESCENDING") {
				finalString = custom.CMapSort.combineMapEntry(custom.CMapSort.sortMapByValue(paraMap,"DESCENDING"), onlyValue, paraConnector);
			}
		}
		
		
		if (howDealKey.equals("appendToEnd")){
			secretKey = textFieldSecretKey.getText();
			finalString += secretKey;
		}
		return finalString;
	}
	
	
	//根据GUI中的有序参数列表，更新当前请求的参数列表。
	public Map<String, String> getUpdatedParaBaseOnTable(IRequestInfo analyzeRequest){
    	List<IParameter> paras = analyzeRequest.getParameters();//当body是json格式的时候，这个方法也可以正常获取到键值对，牛掰。但是PARAM_JSON等格式不能通过updateParameter方法来更新。
    	Map<String,String> paraMap = getParaFromTable();
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
	
	public byte getSignParaType(IRequestInfo analyzeRequest){
		List<IParameter> paras = analyzeRequest.getParameters();//当body是json格式的时候，这个方法也可以正常获取到键值对，牛掰。但是PARAM_JSON等格式不能通过updateParameter方法来更新。
		byte signParaType = -1;
		for (IParameter para:paras){
    		if (para.getName().equals(signPara)){
    			signParaType = para.getType();
    			
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
	
	public Map<String, String> getParaFromTable(){
		Map<String, String> tableParas = new LinkedHashMap<String, String>();
    	for (int i=0; i<table.getRowCount();i++){
    		//System.out.println(table.getRowCount());
    		String key = table.getValueAt(i, 0).toString();
    		//System.out.println(key);
    		String value = table.getValueAt(i, 1).toString();
    		//System.out.println(value);

    		if (!key.equals(getSignPara())){
    			tableParas.put(key, value);
    		}
    	}
    	System.out.println(tableParas);
    	return tableParas;
	}
	
	public String getHost(IRequestInfo analyzeRequest){
    	List<String> headers = analyzeRequest.getHeaders();
    	String domain = "";
    	for(String item:headers){
    		if (item.toLowerCase().contains("host")){
    			domain = new String(item.substring(6));
    		}
    	}
    	return domain ;
	}
	
	public String getHostFromUI(){
    	String domain = "";
    	domain = textFieldDomain.getText();
    	return domain ;
	}
	//各种从图形面板或者从数据包获取参数，获取配置的函数。--end

	
	
	//以下是各种burp必须的方法 --start
    
    public void addMenuTab()
    {
      SwingUtilities.invokeLater(new Runnable()
      {
        public void run()
        {
          BurpExtender.this.CGUI();
          BurpExtender.this.callbacks.addSuiteTab(BurpExtender.this); //这里的BurpExtender.this实质是指ITab对象，也就是getUiComponent()中的contentPane.这个参数由CGUI()函数初始化。
          //如果这里报java.lang.NullPointerException: Component cannot be null 错误，需要排查contentPane的初始化是否正确。
        }
      });
    }
    
    
    
    //ITab必须实现的两个方法
	@Override
	public String getTabCaption() {
		// TODO Auto-generated method stub
		return ("ReSign");
	}
	@Override
	public Component getUiComponent() {
		// TODO Auto-generated method stub
		return this.contentPane;
	}
	//ITab必须实现的两个方法
	
	
	
	//IContextMenuFactory 必须实现的方法
	@Override
	public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation)
	{ //需要在签名注册！！callbacks.registerContextMenuFactory(this);
	    IHttpRequestResponse[] messages = invocation.getSelectedMessages();
	    List<JMenuItem> list = new ArrayList<JMenuItem>();
	    if((messages != null) && (messages.length > 0))
	    {
	        //this.callbacks.printOutput("Messages in array: " + messages.length);
	        
	        //final IHttpService service = messages[0].getHttpService();
	    	final byte[] sentRequestBytes = messages[0].getRequest();
	    	IRequestInfo analyzeRequest = helpers.analyzeRequest(sentRequestBytes);
	    	
	        JMenuItem menuItem = new JMenuItem("Send to ReSign");
	        menuItem.addActionListener(new ActionListener()
	        {
	          public void actionPerformed(ActionEvent e)
	          {
	            try
	            {
	            	textFieldDomain.setText(getHost(analyzeRequest));
	            	
	            	DefaultTableModel tableModel = (DefaultTableModel) table.getModel();
	            	tableModel.setRowCount(0);//为了清空之前的数据
	            	
	            	Map<String,String> paraMap = getPara(analyzeRequest);
	            	//stdout.println(paraMap);
	            	//stdout.print(paraMap.keySet());
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