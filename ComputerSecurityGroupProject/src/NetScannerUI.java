import java.awt.EventQueue;
import java.awt.FileDialog;
import javax.swing.JFrame;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.border.EtchedBorder;
import javax.swing.JTextField;
import javax.swing.RowFilter;
import javax.swing.UIManager;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JButton;
import java.awt.Font;
import java.io.File;
import java.io.IOException;
import java.io.PrintWriter;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.Socket;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.swing.border.TitledBorder;
import java.awt.Color;
import java.awt.event.ActionListener;
import java.awt.event.ActionEvent;
import javax.swing.JTable;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableRowSorter;
import javax.swing.JScrollPane;
import javax.swing.JProgressBar;
import java.awt.event.KeyAdapter;
import java.awt.event.KeyEvent;
import javax.swing.JTextPane;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import javax.swing.ImageIcon;
import java.awt.Cursor;
import javax.swing.JRadioButton;
import javax.swing.ButtonGroup;
import javax.swing.JCheckBox;


public class NetScannerUI {

	private JFrame formAdvancedPortScanner;
	private JTextField txtIpAddresses;
	private JTextField txtSearchBar;
	private JLabel lblInvalidIpRange;
	private JLabel lblInvalidTcpPortRange;
	private JButton btnScanIP;
	private JButton btnScanTCP;
	private JButton btnScanUDP;
	private JButton btnStopScan;
	private JLabel lblOngoingTask;
	private JScrollPane scrollPane;
	private JTable tableScanner;
	private JProgressBar progressBar;
	private JTextField txtTcpPorts;
	private JPanel panel_4_1;
	private JTextField txtUdpPorts;
	private JLabel lblInvalidUdpPortRange;
	private JPanel panel_7;
	private JScrollPane scrollPane_1;
	private JTextPane txtResultPane;
	private JButton btnExportToFile;
	private JButton btnWakeOnLan;
	private JButton btnRemoteShutdown;
	private JPanel panel_8;
	private JPanel panel_9;
	private JButton btnSwapNetworkInterface;
	
	String subnet = null; // to store the first 3 segment of the IP address
	int startIpEndSegment = 0; // to store the end segment of the start IP
	int endIpEndSegment = 0; // to store the end segment of the end IP
	
	// store start & end ip from text field
	static String startIP = "";
	static String endIP = "";
	
	// to store start & end ports form text field
	String stringStartTcpPort = "";
	String stringEndTcpPort = "";
	String stringStartUdpPort = "";
	String stringEndUdpPort = "";
	
	// default initial boundaries for TCP ports
	final int defaultStartTCP = 1;
	final int defaultEndTCP = 180;
	
	// default initial boundaries for UDP ports
	final int defaultStartUDP = 1;
	final int defaultEndUDP = 10;
	
	// to store the boundaries of TCP ports
	int startTcpPort = -1;
	int endTcpPort = -1;
	
	// to store the boundaries of UDP ports
	int startUdpPort = -1;
	int endUdpPort = -1;
	
	final String dummySubnet = "1.1.1.";
	
	volatile static ArrayList<String> ipAddressesInRange = new ArrayList<String>(); // store IP addresses within specified range for scanning
	volatile static ArrayList<String> aliveIpAddresses = new ArrayList<String>(); // store alive IP addresses after scanning
	volatile static ArrayList<String> operatingSystem = new ArrayList<String>(); // store the Operating System for IPs
	volatile static ArrayList<String> macAddresses = new ArrayList<String>(); // store MAC address for IP addresses
	volatile static ArrayList<Integer> tcpPortsInRange = new ArrayList<Integer>(); // store tcp ports within a specified range for scanning
	volatile static ArrayList<Integer> udpPortsInRange = new ArrayList<Integer>(); // store tcp ports within a specified range for scanning
	volatile static ArrayList<String> aliveTcpPorts = new ArrayList<String>(); // stores alive tcp ports after scanning
	volatile static ArrayList<String> aliveUdpPorts = new ArrayList<String>(); // stores alive udp ports after scanning
	
	// stores the amount of running threads for types of scan
	volatile static int amtTcpThreads = 0;
	volatile static int amtUdpThreads = 0;
	
	// stores the amount of scan made
	volatile static int endedIP = 0;
	volatile static int endedTCP = 0;
	volatile static int endedUDP = 0;
	
	volatile static int crashedTCP = 0;
	
	// maximum thread t allocate to scans
	final int maxIpThread = 100;
	final int maxTcpThread = 100;
	final int maxUdpThread = 100;
	
	final int progressBarMaxPercentage = 95; // upper bound for progress bar
	double progressBarFormula = 0; // stores the formula for progress bar (ip, tcp & udp scan)
	
	// flag to indicate whether a type of scan has ended
	volatile static boolean ipScanEnded = false; 
	volatile static boolean tcpScanEnded = false;
	volatile static boolean udpScanEnded = false;
	
	// flag for whether the types of ports are to be scanned
	boolean tcpScanFlag = false;
	boolean udpScanFlag = false;
	
	// keep track of unscanned and scanned IP addresses
	volatile static int amtUnscannedIP = 0;
	volatile static int amtScannedIP = 0;
	
	// keep track of unscanned and scanned TCP ports
	volatile static int amtUnscannedTCP = 0;
	volatile static int amtScannedTCP = 0;
	
	// keep track of unscanned and scanned UDP ports
	volatile static int amtUnscannedUDP = 0;
	volatile static int amtScannedUDP = 0;
	
	// keep track of IP address index from table when scanning ports
	volatile int indexForIpTCP = 0;
	volatile int indexForIpUDP = 0;
	
	private static final int WakeOnLanPORT = 9; // default wake on lan port
	
	volatile static boolean stopThreads = false; // flag to indicate whether the stop threads to stop scanning
	volatile static boolean isScanning = false; // flag to indicate whether a scan is occurring or not
	
	boolean swappedNetworkInterface = false;
	private JRadioButton rdbtnList;
	private JRadioButton rdbtnTable;
	private final ButtonGroup buttonGroup = new ButtonGroup();
	private JLabel lblExportAs;
	private JCheckBox chckbxPromptRemoteMachineLogin;
	

	/**
	 * Launch the application.
	 */
	public static void main(String[] args) {
		EventQueue.invokeLater(new Runnable() {
			public void run() {
				
				try {
					try {
			            // select Look and Feel
//			            UIManager.setLookAndFeel("com.jtattoo.plaf.smart.SmartLookAndFeel");
//			            UIManager.setLookAndFeel("com.jtattoo.plaf.mint.MintLookAndFeel");
			            UIManager.setLookAndFeel("com.jtattoo.plaf.graphite.GraphiteLookAndFeel");
			            // start application
			            NetScannerUI window = new NetScannerUI();
						window.formAdvancedPortScanner.setVisible(true);
					}
			        catch (Exception ex) {
			            ex.printStackTrace();
			        }
//					NetScannerUI window = new NetScannerUI();
//					window.formAdvancedPortScanner.setVisible(true);
				} catch (Exception e) {
					e.printStackTrace();
				}
			}
		});
	}

	/**
	 * Create the application.
	 */
	private NetScannerUI() {
		initialize();
		setIpRange(getHostIP()); // add a default ip scan range upon start
		setPortsRange();
		changeStateOfButtons(true);
	}

	/**
	 * Initialize the contents of the frame.
	 */
	private void initialize() {
		formAdvancedPortScanner = new JFrame();
		formAdvancedPortScanner.getContentPane().setFocusable(false);
		formAdvancedPortScanner.setTitle("Advanced Port Scanner");
		formAdvancedPortScanner.setResizable(false);
		formAdvancedPortScanner.setBounds(100, 100, 1110, 700);
		formAdvancedPortScanner.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		formAdvancedPortScanner.getContentPane().setLayout(null);
		
		JPanel panel = new JPanel();
		panel.setFocusable(false);
		panel.setBorder(new EtchedBorder(EtchedBorder.LOWERED, null, null));
		panel.setBounds(10, 147, 717, 501);
		formAdvancedPortScanner.getContentPane().add(panel);
		panel.setLayout(null);
		
		rdbtnList = new JRadioButton("List");
		rdbtnList.setFocusable(false);
		buttonGroup.add(rdbtnList);
		rdbtnList.setBounds(105, 467, 67, 23);
		panel.add(rdbtnList);
		
		scrollPane = new JScrollPane();
		scrollPane.setFocusable(false);
		scrollPane.setBounds(10, 11, 697, 380);
		panel.add(scrollPane);
		
		tableScanner = new JTable();
		tableScanner.setFocusable(false);
		tableScanner.addMouseListener(new MouseAdapter() {
			@Override
			public void mousePressed(MouseEvent e) {
				getRowFromTable();
			}
		});
		scrollPane.setViewportView(tableScanner);
		tableScanner.setModel(new DefaultTableModel(
			new Object[][] {
			},
			new String[] {
				"IP Address", "Operating System", "MAC Address", "TCP Ports", "UDP Ports"
			}
		) {
			/**
			 * 
			 */
			private static final long serialVersionUID = 1L;
			boolean[] columnEditables = new boolean[] {
				false, false, false, false, false
			};
			public boolean isCellEditable(int row, int column) {
				return columnEditables[column];
			}
		});
		
		panel_9 = new JPanel();
		panel_9.setFocusable(false);
		panel_9.setBounds(10, 400, 600, 60);
		panel.add(panel_9);
		panel_9.setLayout(null);
		
		progressBar = new JProgressBar();
		progressBar.setFocusable(false);
		progressBar.setBounds(0, 0, 200, 15);
		panel_9.add(progressBar);
		progressBar.setStringPainted(true);
		
		JLabel lblNewLabel = new JLabel("Task:");
		lblNewLabel.setFocusable(false);
		lblNewLabel.setBounds(220, 0, 40, 14);
		panel_9.add(lblNewLabel);
		lblNewLabel.setForeground(new Color(178, 34, 34));
		lblNewLabel.setFont(new Font("MS Reference Sans Serif", Font.PLAIN, 12));
		
		panel_8 = new JPanel();
		panel_8.setFocusable(false);
		panel_8.setBounds(0, 34, 600, 26);
		panel_9.add(panel_8);
		panel_8.setLayout(null);
		
		btnExportToFile = new JButton("Export to File");
		btnExportToFile.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
		btnExportToFile.setFocusable(false);
		btnExportToFile.setIcon(new ImageIcon(NetScannerUI.class.getResource("/images/icons8-save-20.png")));
		btnExportToFile.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				exportToFile();
			}
		});
		btnExportToFile.setBounds(0, 0, 180, 25);
		panel_8.add(btnExportToFile);
		
		btnWakeOnLan = new JButton("Wake on Lan");
		btnWakeOnLan.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
		btnWakeOnLan.setFocusable(false);
		btnWakeOnLan.setIcon(new ImageIcon(NetScannerUI.class.getResource("/images/icons8-ethernet-on-25.png")));
		btnWakeOnLan.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				wakeOnLan();
			}
		});
		btnWakeOnLan.setBounds(210, 1, 180, 25);
		panel_8.add(btnWakeOnLan);
		
		btnRemoteShutdown = new JButton("Remote Shutdown");
		btnRemoteShutdown.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
		btnRemoteShutdown.setFocusable(false);
		btnRemoteShutdown.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				remoteShutdown();
			}
		});
		btnRemoteShutdown.setIcon(new ImageIcon(NetScannerUI.class.getResource("/images/icons8-shutdown-20.png")));
		btnRemoteShutdown.setBounds(420, 1, 180, 25);
		panel_8.add(btnRemoteShutdown);
		
		lblOngoingTask = new JLabel("Null");
		lblOngoingTask.setFocusable(false);
		lblOngoingTask.setBounds(260, 0, 260, 14);
		panel_9.add(lblOngoingTask);
		lblOngoingTask.setForeground(new Color(178, 34, 34));
		lblOngoingTask.setFont(new Font("MS Reference Sans Serif", Font.PLAIN, 12));
		
		rdbtnTable = new JRadioButton("Table");
		rdbtnTable.setSelected(true);
		rdbtnTable.setFocusable(false);
		buttonGroup.add(rdbtnTable);
		rdbtnTable.setBounds(44, 467, 59, 23);
		panel.add(rdbtnTable);
		
		lblExportAs = new JLabel("As:");
		lblExportAs.setFocusable(false);
		lblExportAs.setFont(new Font("MS Reference Sans Serif", Font.ITALIC, 15));
		lblExportAs.setBounds(12, 470, 39, 14);
		panel.add(lblExportAs);
		
		chckbxPromptRemoteMachineLogin = new JCheckBox("Login To Remote Machine");
		chckbxPromptRemoteMachineLogin.setFocusable(false);
		chckbxPromptRemoteMachineLogin.setBounds(427, 467, 229, 23);
		panel.add(chckbxPromptRemoteMachineLogin);
		tableScanner.getColumnModel().getColumn(0).setResizable(false);
		tableScanner.getColumnModel().getColumn(1).setResizable(false);
		
		JPanel panel_1 = new JPanel();
		panel_1.setFocusable(false);
		panel_1.setBorder(new EtchedBorder(EtchedBorder.LOWERED, null, null));
		panel_1.setBounds(737, 147, 347, 488);
		formAdvancedPortScanner.getContentPane().add(panel_1);
		panel_1.setLayout(null);
		
		scrollPane_1 = new JScrollPane();
		scrollPane_1.setFocusable(false);
		scrollPane_1.setBounds(10, 11, 327, 466);
		panel_1.add(scrollPane_1);
		
		txtResultPane = new JTextPane();
		txtResultPane.setFont(new Font("Monospaced", Font.PLAIN, 15));
		txtResultPane.setEditable(false);
		scrollPane_1.setViewportView(txtResultPane);
		
		JPanel panel_2 = new JPanel();
		panel_2.setFocusable(false);
		panel_2.setBorder(new EtchedBorder(EtchedBorder.LOWERED, null, null));
		panel_2.setBounds(10, 11, 1074, 125);
		formAdvancedPortScanner.getContentPane().add(panel_2);
		panel_2.setLayout(null);
		
		JPanel panel_5 = new JPanel();
		panel_5.setFocusable(false);
		panel_5.setBounds(53, 11, 961, 67);
		panel_2.add(panel_5);
		panel_5.setLayout(null);
		
		JPanel panel_3 = new JPanel();
		panel_3.setFocusable(false);
		panel_3.setBounds(0, 0, 392, 54);
		panel_5.add(panel_3);
		panel_3.setBorder(new TitledBorder(new EtchedBorder(EtchedBorder.LOWERED, new Color(255, 255, 255), new Color(160, 160, 160)), "IP Address Range", TitledBorder.LEADING, TitledBorder.TOP, null, new Color(0, 0, 0)));
		panel_3.setLayout(null);
		
		txtIpAddresses = new JTextField();
		txtIpAddresses.setToolTipText("Format eg: 192.168.1.1 - 254");
		txtIpAddresses.setBounds(10, 16, 372, 30);
		panel_3.add(txtIpAddresses);
		txtIpAddresses.setColumns(10);
		
		btnScanIP = new JButton("Scan");
		btnScanIP.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
		btnScanIP.setFocusable(false);
		btnScanIP.setIcon(new ImageIcon(NetScannerUI.class.getResource("/images/icons8-play-20.png")));
		btnScanIP.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				beginIpScan();
			}
		});
		btnScanIP.setBounds(432, 10, 121, 40);
		panel_5.add(btnScanIP);
		
		lblInvalidIpRange = new JLabel("Invalid IP Address Range");
		lblInvalidIpRange.setFocusable(false);
		lblInvalidIpRange.setVisible(false);
		lblInvalidIpRange.setBounds(10, 53, 164, 14);
		panel_5.add(lblInvalidIpRange);
		lblInvalidIpRange.setForeground(Color.RED);
		lblInvalidIpRange.setFont(new Font("MS Reference Sans Serif", Font.PLAIN, 10));
		
		JPanel panel_4 = new JPanel();
		panel_4.setFocusable(false);
		panel_4.setLayout(null);
		panel_4.setBorder(new TitledBorder(new EtchedBorder(EtchedBorder.LOWERED, new Color(255, 255, 255), new Color(160, 160, 160)), "TCP Port Range", TitledBorder.LEADING, TitledBorder.TOP, null, new Color(0, 0, 0)));
		panel_4.setBounds(593, 0, 166, 54);
		panel_5.add(panel_4);
		
		txtTcpPorts = new JTextField();
		txtTcpPorts.setToolTipText("Format eg: 1 - 180");
		txtTcpPorts.setColumns(10);
		txtTcpPorts.setBounds(10, 16, 146, 30);
		panel_4.add(txtTcpPorts);
		
		panel_4_1 = new JPanel();
		panel_4_1.setFocusable(false);
		panel_4_1.setLayout(null);
		panel_4_1.setBorder(new TitledBorder(new EtchedBorder(EtchedBorder.LOWERED, new Color(255, 255, 255), new Color(160, 160, 160)), "UDP Port Range", TitledBorder.LEADING, TitledBorder.TOP, null, new Color(0, 0, 0)));
		panel_4_1.setBounds(797, 0, 166, 54);
		panel_5.add(panel_4_1);
		
		txtUdpPorts = new JTextField();
		txtUdpPorts.setToolTipText("Format eg: 1 - 10");
		txtUdpPorts.setColumns(10);
		txtUdpPorts.setBounds(10, 16, 146, 30);
		panel_4_1.add(txtUdpPorts);
		
		lblInvalidTcpPortRange = new JLabel("Invalid Port Range");
		lblInvalidTcpPortRange.setFocusable(false);
		lblInvalidTcpPortRange.setVisible(false);
		lblInvalidTcpPortRange.setBounds(603, 53, 130, 14);
		panel_5.add(lblInvalidTcpPortRange);
		lblInvalidTcpPortRange.setForeground(Color.RED);
		lblInvalidTcpPortRange.setFont(new Font("MS Reference Sans Serif", Font.PLAIN, 10));
		
		lblInvalidUdpPortRange = new JLabel("Invalid Port Range");
		lblInvalidUdpPortRange.setFocusable(false);
		lblInvalidUdpPortRange.setVisible(false);
		lblInvalidUdpPortRange.setForeground(Color.RED);
		lblInvalidUdpPortRange.setFont(new Font("MS Reference Sans Serif", Font.PLAIN, 10));
		lblInvalidUdpPortRange.setBounds(807, 53, 130, 14);
		panel_5.add(lblInvalidUdpPortRange);
		
		JPanel panel_6 = new JPanel();
		panel_6.setFocusable(false);
		panel_6.setBorder(new TitledBorder(null, "Search Filter", TitledBorder.LEADING, TitledBorder.TOP, null, null));
		panel_6.setBounds(53, 78, 392, 45);
		panel_2.add(panel_6);
		panel_6.setLayout(null);
		
		txtSearchBar = new JTextField();
		txtSearchBar.addKeyListener(new KeyAdapter() {
			@Override
			public void keyReleased(KeyEvent e) {
				String query = txtSearchBar.getText().toLowerCase();
				searchFilter(query);
			}
		});
		txtSearchBar.setBounds(10, 16, 372, 25);
		panel_6.add(txtSearchBar);
		txtSearchBar.setColumns(10);
		
		panel_7 = new JPanel();
		panel_7.setFocusable(false);
		panel_7.setBounds(656, 80, 350, 25);
		panel_2.add(panel_7);
		panel_7.setLayout(null);
		
		btnScanTCP = new JButton("TCP Scan");
		btnScanTCP.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
		btnScanTCP.setFocusable(false);
		btnScanTCP.setIcon(new ImageIcon(NetScannerUI.class.getResource("/images/icons8-play-20.png")));
		btnScanTCP.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				readyForPortScan("TCP");
			}
		});
		btnScanTCP.setBounds(0, 0, 146, 25);
		panel_7.add(btnScanTCP);
		
		btnScanUDP = new JButton("UDP Scan");
		btnScanUDP.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
		btnScanUDP.setFocusable(false);
		btnScanUDP.setIcon(new ImageIcon(NetScannerUI.class.getResource("/images/icons8-play-20.png")));
		btnScanUDP.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				readyForPortScan("UDP");
			}
		});
		btnScanUDP.setBounds(204, 0, 146, 25);
		panel_7.add(btnScanUDP);
		
		btnStopScan = new JButton("Stop Scan");
		btnStopScan.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
		btnStopScan.setFocusable(false);
		btnStopScan.setIcon(new ImageIcon(NetScannerUI.class.getResource("/images/icons8-stop-20.png")));
		btnStopScan.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				stopAllThreads();
			}
		});
		btnStopScan.setBounds(486, 80, 121, 25);
		panel_2.add(btnStopScan);
		
		btnSwapNetworkInterface = new JButton("");
		btnSwapNetworkInterface.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
		btnSwapNetworkInterface.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				swapNetworkInterface();
			}
		});
		btnSwapNetworkInterface.setFocusable(false);
		btnSwapNetworkInterface.setIcon(new ImageIcon(NetScannerUI.class.getResource("/images/icons8-available-updates-20.png")));
		btnSwapNetworkInterface.setToolTipText("switch network interace");
		btnSwapNetworkInterface.setBounds(25, 30, 25, 25);
		btnSwapNetworkInterface.setOpaque(false);
		btnSwapNetworkInterface.setContentAreaFilled(false);
		btnSwapNetworkInterface.setBorderPainted(false);
		panel_2.add(btnSwapNetworkInterface);
		
		JLabel lblSignature = new JLabel("~dp");
		lblSignature.setFocusable(false);
		lblSignature.setBounds(1051, 633, 55, 27);
		formAdvancedPortScanner.getContentPane().add(lblSignature);
		lblSignature.setFont(new Font("Segoe Print", Font.PLAIN, 15));
		
		formAdvancedPortScanner.setLocationRelativeTo(null);
				
	}
	
	
	
	
	// ----------------------------------------------------------------------------------------------------------/
	/** CODING BEGINS BELOW			CODING BEGINS BELOW			CODING BEGINS BELOW			CODING BEGINS BELOW	*/
	// ----------------------------------------------------------------------------------------------------------/
	
		
	
	

	/** Reset Components ------------- Start */
	
	// reset components associated with IP scan
	private void resetForIpScan() {
		DefaultTableModel tableModel = (DefaultTableModel) tableScanner.getModel();
		tableModel.setRowCount(0); // reset table
		
		amtUnscannedIP = 0;
		amtScannedIP = 0;
		ipScanEnded = false;
		stopThreads = false;
		progressBarFormula = 0;
		txtResultPane.setText("");
		
		ipAddressesInRange.clear();
		aliveIpAddresses.clear();
		operatingSystem.clear();
		macAddresses.clear();
		aliveTcpPorts.clear();
		aliveUdpPorts.clear();
		
		btnExportToFile.setEnabled(false);
		btnWakeOnLan.setEnabled(false);
		btnRemoteShutdown.setEnabled(false);
		
		progressBar.setValue(0);
//		showProgress(0);
	}
	
	// reset components associated TCP scan
	private void resetForTcpScan() {
		amtUnscannedTCP = 0;
		amtScannedTCP = 0;
		indexForIpTCP = 0;
		tcpScanEnded = false;
		tcpScanFlag = false;
		tcpPortsInRange.clear();
		amtTcpThreads = 0;
		endedTCP = 0;
		crashedTCP = 0;
		startTcpPort = -1;
		endTcpPort = -1;
		stopThreads = false;
		txtResultPane.setText("");

		// clear ports
		for (int i = 0; i < aliveTcpPorts.size(); i++) {
			aliveTcpPorts.set(i, "");
		}
		
		populateTable();
//		showProgress(0);
		progressBar.setValue(0);
	}
	
	// reset components associated with UDP scan
	private void resetForUdpScan() {
		amtUnscannedUDP = 0;
		amtScannedUDP = 0;
		indexForIpUDP = 0;
		udpScanEnded = false;
		udpScanFlag = false;
		udpPortsInRange.clear();
		amtUdpThreads = 0;
		endedUDP = 0;
		startUdpPort = -1;
		endUdpPort = -1;
		stopThreads = false;
		txtResultPane.setText("");

		// clear ports
		for (int i = 0; i < aliveUdpPorts.size(); i++) {
			aliveUdpPorts.set(i, "");
		}
		
		populateTable();
//		showProgress(0);
		progressBar.setValue(0);
	}
	/** Reset Components ------------- End */
	
	
	
	
	
	
	
	
	/** Relating to IP Address (Ping) ---------------- Start */
	
	// set initial IP range based IP address parameter
	private void setIpRange(String myIP) {
		String[] ipSegments = myIP.split("\\.");
		String subnet_ = ipSegments[0] + "." + ipSegments[1] + "." + ipSegments[2] + ".";

		// display IP address range IP address text field
		txtIpAddresses.setText((subnet_ + 1) + " - " + (254));
	}
			
	// get IP of host machine
	private String getHostIP() {

		try {
			DatagramSocket socket = new DatagramSocket();
			socket.connect(InetAddress.getByName("8.8.8.8"), 10002);
			String hostIP = socket.getLocalAddress().getHostAddress();
			socket.close();

			return hostIP;
//			setIpRange(hostIP); // set range based on host IP

		} catch (SocketException e) {
			e.printStackTrace();
		} catch (UnknownHostException e) {
			e.printStackTrace();
		}
		return "127.0.0.1";
	}
	
	// get IP of host machine if virtual box is installed
	private String getVirtualHostIP() {
		
		try { 
			String hostIP = InetAddress.getLocalHost().getHostAddress();
			return hostIP;
			
		} catch (UnknownHostException uhe) {
		  uhe.printStackTrace();
		}
		return "127.0.0.1";
	}
	
	// used to validate IPv4 address format
	private boolean isValidInet4Address(String ip) {

		try {
			return Inet4Address.getByName(ip).getHostAddress().equals(ip); // return true if IP format is valid
		} catch (UnknownHostException e) {
			return false; // return false if IP format is invalid
		}
	}
	
	// used to check that the indicated IP range is valid
	private boolean validateIpRange(String startIP, String endIP) {
		String[] startParts = startIP.split("\\."); // split segments of the IP address separated by '.'

		// compare if first IP is larger than or equal to last IP address 
		if (Integer.parseInt(startParts[3]) >= Integer.parseInt(endIP)) {
			return false; // returns false if IP range is not valid
		}

		subnet = startParts[0] + "." + startParts[1] + "." + startParts[2] + "."; // store subnet of IP
		startIpEndSegment = Integer.parseInt(startParts[3]); // store end segment of first IP
		endIpEndSegment = Integer.parseInt(endIP); // store end segment of last IP

		return true; // return true if IP range is valid
	}
	
	// check if IP addresses entered valid & are within valid range
	private boolean validateIpAddresses() {

		/** if addresses are invalid the a label is displayed to indicate so */

		boolean isValidAddr = false; // flag to indicate if IP addresses are valid

		// validate staring IP
		if (isValidInet4Address(startIP)) {
			isValidAddr = true; // starting is address is valid
			lblInvalidIpRange.setVisible(false); // hide invalid IP range message
		} else {
			lblInvalidIpRange.setVisible(true); // display invalid IP range message
		}

		// if starting IP address was valid
		if (isValidAddr) {
			// validate ending IP appending the last segment to a dummy subnet
			if (isValidInet4Address(dummySubnet + endIP)) {
				if (isValidAddr) {
					isValidAddr = true; // ending IP address is valid
				}
			} else { // ending IP address is not valid
				isValidAddr = false; // ending IP address is invalid
				lblInvalidIpRange.setVisible(true); // display invalid IP range message
			}
		}

		// validate IP range, if starting & ending IP's are of valid format
		if (isValidAddr) {
			if (validateIpRange(startIP, endIP)) {
				return true; // return true if IP addresses & range is valid
			} else {
				lblInvalidIpRange.setVisible(true); // display invalid IP range message
			}
		}

		return false; // return false if IP address &/or range is invalid
	}
		
	// store IP addresses within the range in a list
	private void setIpAddressesInRange() {
		amtUnscannedIP = endIpEndSegment - startIpEndSegment; // the amount of IP's to be scanned
		
		// formula for progress bar when scanning IP addresses
		progressBarFormula = ((double) progressBarMaxPercentage) /  ((double) amtUnscannedIP); 
		int ipSegment = startIpEndSegment; // the starting IP address last segment

		// iterate from the starting IP address' last segment to the amount of address to be scanned
		for (int i = 0; i <= amtUnscannedIP; i++) {
			ipAddressesInRange.add(subnet + ipSegment); // IP addresses to be scanned
			ipSegment++;
		}
	}
		
	// read IP addresses from format used in text field
	private void readMultipleIpAddress() {
		String ipAddr = txtIpAddresses.getText();
		startIP = endIP = "";
		
		if (ipAddr.contains("-")) {
			// split text to get IP addresses from format
			String[] seg = ipAddr.split("\\-"); 
			
			// if only 2 IP address was from the format used in the text field
			if (seg.length == 2) {
				startIP = seg[0].trim();
				endIP = seg[1].trim();
			}
		}
	}
	/** Relating to IP Address (Ping) ---------------- End */
	
	
	
	
	
	
	
	
	/** Relating to Ports ---------------- Start */
	
	// set initial port ranges in text fields
	private void setPortsRange() {
		txtTcpPorts.setText(defaultStartTCP + " - " + defaultEndTCP); // range for TCP ports
		txtUdpPorts.setText(defaultStartUDP + " - " + defaultEndUDP); // range for UDP ports
	}
	
	
	// read TCP & UDP ports from format used in text fields
	private void readMultiplePorts(String portType) {
		
		// if TCP ports was requested to be read from text field
		if (portType.equalsIgnoreCase("TCP")) {
			
			String tcpPorts = txtTcpPorts.getText(); // get entry from text field
			stringStartTcpPort = stringEndTcpPort = "";
			
			// if text field was empty...
			if (tcpPorts.isEmpty()) {
				tcpScanFlag = false; // set flag to not scan TCP ports
			} 
			else {
				tcpScanFlag = true; // set flag to scan TCP ports

				if (tcpPorts.contains("-")) {
					// split text to get TCP ports from format
					String[] seg = tcpPorts.split("\\-");

					// if only 2 ports was entered in text field to be used as TCP range
					if (seg.length == 2) {
						stringStartTcpPort = seg[0].trim();
						stringEndTcpPort = seg[1].trim();
					}
				}
			}
		}
		
		// if UDP ports was requested to be read from text field 
		else if (portType.equalsIgnoreCase("UDP")) {
			
			String udpPorts = txtUdpPorts.getText(); // get entry from text field
			stringStartUdpPort = stringEndUdpPort = "";
			
			// if text field was empty...
			if (udpPorts.isEmpty()) {
				udpScanFlag = false; // set flag to not scan UDP ports
			} 
			else {
				udpScanFlag = true; // set flag to scan UDP ports

				if (udpPorts.contains("-")) {
					// split text to get UDP ports from format
					String[] seg = udpPorts.split("\\-");

					// if only 2 ports was entered in text field to be used as UDP range
					if (seg.length == 2) {
						stringStartUdpPort = seg[0].trim();
						stringEndUdpPort = seg[1].trim();
					}
				}
			}
		}
	}
	
	// validate converting string from port text fields to integer values
	private boolean validatePortParsing(String portType) {
		
		// if TCP port validation is requested
		if (portType.equalsIgnoreCase("TCP")) {
			if (tcpScanFlag == false) { // is TCP port was set to not be scanned...
				lblInvalidTcpPortRange.setVisible(false); // hide invalid port range label
				return true; // return true that it is valid
			}
			
			// try convert string to integer
			try {
				startTcpPort = Integer.parseInt(stringStartTcpPort.trim());
				endTcpPort = Integer.parseInt(stringEndTcpPort.trim());
			}
			catch (NumberFormatException nfe) {
				lblInvalidTcpPortRange.setVisible(true); // display invalid TCP port range label
				return false; // failed to convert from string to integer
			}
			
			lblInvalidTcpPortRange.setVisible(false); // hide invalid TCP range label
			return true; // success with converting from ports from string to integer
		}
		
		// if UDP port validation is requested
		else if (portType.equalsIgnoreCase("UDP")) {
			if (udpScanFlag == false) { // is UDP port was set to not be scanned...
				lblInvalidUdpPortRange.setVisible(false); // hide invalid port range label
				return true; // return true that it is valid
			}
			
			// try convert string to integer
			try {
				startUdpPort = Integer.parseInt(stringStartUdpPort.trim());
				endUdpPort = Integer.parseInt(stringEndUdpPort.trim());
			} 
			catch (NumberFormatException nfe) {
				lblInvalidUdpPortRange.setVisible(true); // display invalid UDP port range label
				return false; // failed to convert from string to integer
			}
			
			lblInvalidUdpPortRange.setVisible(false); // hide invalid UDP range label
			return true; // success with converting from ports from string to integer
		}
		
		return false;
	}
	
	// validate the ports range entered
	private boolean validatePortRange(String portType) {

		// if TCP port range validation was requested
		if (portType.equalsIgnoreCase("TCP")) { 
			if (tcpScanFlag == false) { // if TCP port was set to not be scanned...
				lblInvalidTcpPortRange.setVisible(false); // hide invalid TCP range label
				return true; // return true that range is valid
			}
			
			// if start or end TCP port in range is less than zero (0)
			if (startTcpPort < 0 || endTcpPort < 0) {
				lblInvalidTcpPortRange.setVisible(true); // display invalid range label
				return false; // invalid port range
			}
			// if start or end TCP port in range is greater than (65535)
			else if (startTcpPort > 65535 || endTcpPort > 65535) {
				lblInvalidTcpPortRange.setVisible(true); // display invalid range label
				return false; // invalid port range
			}
			// if start port is less than end port for range
			else if (startTcpPort < endTcpPort) {
				lblInvalidTcpPortRange.setVisible(false); // hide invalid range label
				return true; // port range is valid
			}
			else { // port range is otherwise invalid
				lblInvalidTcpPortRange.setVisible(true); // display invalid range label
				return false; // port range is invalid
			}
		}
		
		// if UDP port range validation was requested
		else if (portType.equalsIgnoreCase("UDP")) { 
			if (udpScanFlag == false) { // if UDP port was set to not be scanned...
				lblInvalidUdpPortRange.setVisible(false); // hide invalid UDP range label
				return true; // return true that range is valid
			}
			
			// if start or end UDP port in range is less than zero (0)
			if (startUdpPort < 0 || endUdpPort < 0) {
				lblInvalidUdpPortRange.setVisible(true); // display invalid range label    
				return false; // invalid port range
			}
			// if start or end UDP port in range is greater than (65535)
			else if (startUdpPort > 65535 || endUdpPort > 65535) {
				lblInvalidUdpPortRange.setVisible(true); // display invalid range label
				return false; // invalid port range
			}
			// if start port is less than end port for range
			else if (startUdpPort < endUdpPort) {
				lblInvalidUdpPortRange.setVisible(false); // hide invalid range label
				return true; // port range is valid
			}
			else { // port range is otherwise invalid
				lblInvalidUdpPortRange.setVisible(true); // display invalid range label
				return false; // invalid port range
			}
		}
		
		return false;			
	}
	/** Relating to Ports ---------------- End */
	
	
	
	
	
	
	
	
	/** Some Utility Methods ------------------ Start */
	
	private void swapNetworkInterface() {
		if (swappedNetworkInterface == false) {
			setIpRange(getVirtualHostIP());
			swappedNetworkInterface = true;
		} else {
			setIpRange(getHostIP());
			swappedNetworkInterface = false;
		}
	}
	
	// update progress on progress bar
	private void showProgress(int amount) 
    { 
		progressBar.setValue((int) (progressBarFormula * amount)); 
    }
		
	
	// update the displaying table
	private void populateTable() {
		DefaultTableModel tableModel = (DefaultTableModel) tableScanner.getModel();
		tableModel.setRowCount(0); // clear table

		// if the amount of alive IP address is the same as the amount
		// of MAC addresses; as MAC addresses are retrieved slower than IP addresses
		if (aliveIpAddresses.size() == macAddresses.size()) {
			// display table including all columns
			for (int i = 0; i < aliveIpAddresses.size(); i++) {
				tableModel.addRow(new Object[] { aliveIpAddresses.get(i), operatingSystem.get(i), macAddresses.get(i), aliveTcpPorts.get(i), aliveUdpPorts.get(i) });
			}
		}
		else { // otherwise only display only IP & OS column in the meanwhile
			for (int i = 0; i < aliveIpAddresses.size(); i++) {
				tableModel.addRow(new Object[] { aliveIpAddresses.get(i), operatingSystem.get(i) });
			}
		}		
	}
	
	// enable and disable buttons
	private void changeStateOfButtons(boolean state) {
		btnScanIP.setEnabled(state);
		btnScanTCP.setEnabled(state);
		btnScanUDP.setEnabled(state);
		btnStopScan.setEnabled(!state);
		btnExportToFile.setEnabled(state);
		btnWakeOnLan.setEnabled(false);
		btnRemoteShutdown.setEnabled(false);
		isScanning = !state;
		
		if (state)
			btnSwapNetworkInterface.setEnabled(state);
	}
	
	// initiate stopping of threads (scans)
	private void stopAllThreads() {
		lblOngoingTask.setText("Stopping Services...");
		
		btnStopScan.setEnabled(false);
		stopThreads = true; // set flag to initiate stopping of threads
		
		// wait for thread to stop
		try {
			TimeUnit.SECONDS.sleep(12);
		} catch (InterruptedException e) {
			e.printStackTrace();
		}

		// set display for task label that threads were stopped
		lblOngoingTask.setText("Services Successfully Stopped...");
		
		changeStateOfButtons(true); // enable buttons after scan stopped
	}
	
	// filters input search
	private void searchFilter(String query) {
		DefaultTableModel model = (DefaultTableModel) tableScanner.getModel();
		TableRowSorter<DefaultTableModel> tr = new TableRowSorter<DefaultTableModel>(model);
		tableScanner.setRowSorter(tr);
		tr.setRowFilter(RowFilter.regexFilter("(?i)" + query.trim()));
		
		btnRemoteShutdown.setEnabled(false);
		btnWakeOnLan.setEnabled(false);
	}
	
	// dialog to export table
	private void exportToFile() {
		DefaultTableModel tableModel = (DefaultTableModel) tableScanner.getModel();
		int rows = tableModel.getRowCount(); // count rows within table
		
		if (rows < 1) {
			return; // return if table is empty
		}

		// dialog for saving file
		FileDialog fDialog = new FileDialog(formAdvancedPortScanner, "Save", FileDialog.SAVE);
		fDialog.setFile("Advanced Port Scanner Scan.txt"); // default name to save file
		fDialog.setVisible(true); // show dialog to save file

		String path = fDialog.getDirectory() + fDialog.getFile(); // get directory and file name as path

		if (path.equalsIgnoreCase("nullnull")) {
			return; // return, if both getDirectorty and getFile is null (no file was selected)
		}

		String ext = path.substring(path.length() - 4); // get last 4 character of path

		if (!ext.equalsIgnoreCase(".txt")) { 
			path = path + ".txt"; // append .txt to path if it didn't end with .txt
		}

		try {
			File file = new File(path);

			PrintWriter os = new PrintWriter(file);

			// write table to file in table format
			if (rdbtnTable.isSelected()) {
				os.println("--------------------------------------------------------------------------------------------------");
				os.printf("%-17s %-20s %-20s %-20s %-20s %n", "IP Address", "Operating System", "MAC Address", "TCP Ports", "UDP Ports");
				os.println("--------------------------------------------------------------------------------------------------");
				
				for (int row = 0; row < tableScanner.getRowCount(); row++) {
					String IP = tableScanner.getValueAt(row, 0).toString();
					String OS = tableScanner.getValueAt(row, 1).toString();
					String MAC = tableScanner.getValueAt(row, 2).toString();
					String TCP = tableScanner.getValueAt(row, 3).toString();
					String UDP = tableScanner.getValueAt(row, 4).toString();
					
					os.printf("%-17s %-20s %-20s %-20s %-20s %n", IP, OS, MAC, TCP, UDP);
				}
				os.println("--------------------------------------------------------------------------------------------------");
			}
			
			// write table to file in list format
			else if (rdbtnList.isSelected()) {
				for (int row = 0; row < tableScanner.getRowCount(); row++) {
					os.println("-----------------------------------------------------");
					for (int col = 0; col < tableScanner.getColumnCount(); col++) {
						String column = tableScanner.getColumnName(col);
						String cell = tableScanner.getValueAt(row, col).toString();
						os.printf("%-16s %-2s %-20s %n", column, ":", cell);
					}
					os.println("-----------------------------------------------------");
					os.println("");
				}
			}
			
			os.close();

		} catch (IOException e) {
			e.printStackTrace();
		}

	}
	
	// used to get selected row from table & display info in side pane
	private void getRowFromTable() {
		DefaultTableModel model = (DefaultTableModel) tableScanner.getModel();
		int i = tableScanner.getSelectedRow(); // get selected row index
		
		String macAddress = model.getValueAt(i, 2).toString(); // store MAC address from index in table
		
		// display info from table in side pane
		txtResultPane.setText(" IP Address: " + model.getValueAt(i, 0) + "\n"
				+ " Operating System: " + model.getValueAt(i, 1) + "\n"
				+ " MAC Address: " + macAddress + "\n"
				+ " TCP Ports: " + model.getValueAt(i, 3) + "\n"
				+ " UDP Ports: " + model.getValueAt(i, 4) + "\n");
		
		// enable buttons if there is no scanning
		if (!isScanning) {
			
			// if operating system of selected row is WINDOWS
			if (model.getValueAt(i, 1).toString().equalsIgnoreCase("WINDOWS")) {
				btnRemoteShutdown.setEnabled(true);
				
				if (!macAddress.equalsIgnoreCase("")) {
					btnWakeOnLan.setEnabled(true); // enable wake on LAN button if MAC address is not empty
				} else {
					btnWakeOnLan.setEnabled(false); // otherwise disable wake on LAN button
				}
			} else { // if operating system is not WINDOWS
				btnRemoteShutdown.setEnabled(false); // disable remote shutdown button
				btnWakeOnLan.setEnabled(false); // disable wake on LAN button
			}
			
		} else { // if a scan is occurring 
			btnRemoteShutdown.setEnabled(false); // disable remote shutdown button
			btnWakeOnLan.setEnabled(false); // disable wake on LAN button
		}
	}
		
	/** Some Utility Methods ------------------ End */
	
	
	
	
	
	
	
	
	/** Wake-On-Lan --------------- Start */	
	
	// convert MAC address into bytes
	private byte[] getMacBytes(String macStr) throws IllegalArgumentException {
        byte[] bytes = new byte[6];
        String[] hex = macStr.split("(\\:|\\-)");
        if (hex.length != 6) {
            throw new IllegalArgumentException("Invalid MAC address.");
        }
        try {
            for (int i = 0; i < 6; i++) {
                bytes[i] = (byte) Integer.parseInt(hex[i], 16);
            }
        }
        catch (NumberFormatException e) {
            throw new IllegalArgumentException("Invalid hex digit in MAC address.");
        }
        return bytes;
    }
	
	private void wakeOnLan() {
		
		DefaultTableModel model = (DefaultTableModel) tableScanner.getModel();
		int j = tableScanner.getSelectedRow(); // get selected row index from table
		
		String ipAddress = model.getValueAt(j, 0).toString(); // get IP address from table using index
		String macAddress = model.getValueAt(j, 2).toString(); // get MAC from table using index
		
		// if MAC address is not of valid length
		if (macAddress.length() != 17) {
			return; 
		}
		
		String[] ipSegments = ipAddress.split("\\."); // split IP into segments
		
		// use subnet to set host address
		String hostAddress = ipSegments[0] + "." + ipSegments[1] + "." + ipSegments[2] + "." + 255; 
		
        try {
            byte[] macBytes = getMacBytes(macAddress); // convert MAC address into bytes
            
            // create wake on LAN packet
            byte[] bytes = new byte[6 + 16 * macBytes.length];
            for (int i = 0; i < 6; i++) {
                bytes[i] = (byte) 0xff;
            }
            for (int i = 6; i < bytes.length; i += macBytes.length) {
                System.arraycopy(macBytes, 0, bytes, i, macBytes.length);
            }
            
            InetAddress address = InetAddress.getByName(hostAddress);
            
            // send UDP wake on LAN packet
            DatagramPacket packet = new DatagramPacket(bytes, bytes.length, address, WakeOnLanPORT); 
            DatagramSocket socket = new DatagramSocket();
            socket.send(packet);
            socket.close();
            
            JOptionPane.showMessageDialog(null, "Wake-on-LAN packet sent to: " + ipAddress); // display success
        }
        catch (Exception e) {
        	JOptionPane.showMessageDialog(null, "Failed to send Wake-on-LAN packet to: " + ipAddress); // display failure
            return;
        }
	}	
	/** Wake-On-Lan --------------- End */	
	
	
	
	
	
	

	
	/** Remote Shutdown ---------- Start */
	
	// prompt for credentials to login to remote system to shutdown
	private boolean loginToRemoteSystem(String hostname) {
		JTextField username = new JTextField();
		JTextField password = new JPasswordField();
		Object[] message = {
		    "Username:", username,
		    "Password:", password
		};

		int option = JOptionPane.CANCEL_OPTION;
		
		do {
			option = JOptionPane.showConfirmDialog(null, message, "Enter Remote System Credentials", JOptionPane.OK_CANCEL_OPTION);
		} while(username.getText().isBlank() && option == JOptionPane.OK_OPTION);
		// loop if ok is pressed and username field was empty
		
		if (option == JOptionPane.OK_OPTION) {
			
			String command = "net use \\\\" + hostname + " " + password.getText() + " /user:" + username.getText();
			
			try {
				Process proc = Runtime.getRuntime().exec(command); // execute command
				
				// StreamGobbler class to parse executed command
				StreamGobbler outputGobbler = new StreamGobbler(proc.getInputStream(), "OUTPUT"); 
				outputGobbler.start(); 
				proc.waitFor();
				
				// send output to be validated if IP was reachable (ping)
				return validateRemoteLogin(outputGobbler.getOutputLines());
			
			} catch (IOException | InterruptedException ex) {
				JOptionPane.showMessageDialog(null, "Remote System Login Error...");
				return false;
			} 
		} 
		return false;
	}
	
	// validate if remote login was successful or not
	private boolean validateRemoteLogin(List<String> outputLines) {
		for (String line : outputLines) {
			if (line.contains("successfully")) { // login was successful
				return true;
			}
		}
		
		JOptionPane.showMessageDialog(null, "Reasons: \n1. Incorrect username or password... "
				+ "\n2. Remote machine not found... ", "Shutdown Failed", JOptionPane.INFORMATION_MESSAGE, null);
		return false;
	}
	
	// get host name of a IP address
	private String getHostNameByIp(String ip) {
		
		try {
			InetAddress inetAddr = InetAddress.getByName(ip);
			
			String canonicalHostname = inetAddr.getCanonicalHostName();

			return canonicalHostname; // return host name of IP address

		} catch (UnknownHostException e) {
			return "127.0.0.1"; // return an IP address to indicate false
		}
	}
	
	// used to execute remote shutdown command
	private void sendRemoteShutdownCommand(String hostName) {
		
		String command = "shutdown -s -f -m \\\\" + hostName; // shutdown command
		try {
			Runtime.getRuntime().exec(command); // execute command
			JOptionPane.showMessageDialog(null,"Shutdown command sent to: " + hostName); // display success
		} catch (IOException ex) {
			JOptionPane.showMessageDialog(null,"Shutdown Command failed...");
			ex.printStackTrace();
		}
	}
	
	// manage remote shutdown request
	private void remoteShutdown() {
		DefaultTableModel model = (DefaultTableModel) tableScanner.getModel();
		int i = tableScanner.getSelectedRow(); // get index of selected row in table
		
		String ipAddress = model.getValueAt(i, 0).toString(); // get IP address from selected row in table
		
		// if address returned is valid
		if (isValidInet4Address(ipAddress)) {
			if (ipAddress.equalsIgnoreCase(getHostIP()) || ipAddress.equalsIgnoreCase(getVirtualHostIP())) { // if IP is that of the current host machine
				JOptionPane.showMessageDialog(null,"Shutdown of host machine is not allowed..."); // message
				return; // return, preventing shutdown of host machine
			}
			
			String hostName = getHostNameByIp(ipAddress); // get host name of IP address
			
			// if host name is not a returned IP address
			if (!isValidInet4Address(hostName)) {
				
				if (chckbxPromptRemoteMachineLogin.isSelected()) {
					boolean valid = loginToRemoteSystem(hostName);
					
					if (!valid) 
						return;
				}
				sendRemoteShutdownCommand(hostName); // send shutdown command
				return; // return after sending shutdown command
			}
		}
		
		JOptionPane.showMessageDialog(null,"Shutdown Command failed...");
	}
	/** Remote Shutdown ---------- End */
	
	
		
	
	
	
	
	
	
	/** IP Scanning ------ Start */
	
	// begin the scanning process of IP addresses
	private void beginIpScan() {
		
		readMultipleIpAddress(); // read addresses from text field
		
		if (validateIpAddresses()) {
			
			// update currently occurring task
			lblOngoingTask.setText("Scanning Ip's On Network...");
			
			btnSwapNetworkInterface.setEnabled(false);
			changeStateOfButtons(false); // change state of button when scanning
			
			resetForIpScan(); // reset components related to IP scanning
			setIpAddressesInRange(); // function to set array of IP's in specified range to scan
	
			int threads = 0; // amount of threads to create for scanning IP's
			
			// use max specified threads if amount to be scanned is equivalent or greater
			if (amtUnscannedIP >= maxIpThread) 
				threads = maxIpThread;
			else
				threads = amtUnscannedIP;
			
			// create array of Ping class to start multithreading
			IpPing[] ping = new IpPing[threads];
			
			// initialize array
			for (int i = 0; i < threads; i++) {
				ping[i] = new IpPing((Integer.toString(i))); // pass iterative # to be used as thread name
			}
						
			// start the array of threads
			for (int i = 0; i < threads; i++) {
				ping[i].start();
			}
		}
	}
	
	// used to check for keywords from output to determine if IP is alive or not
	private /* TODO static was here */  boolean checkAvailability(List<String> outputLines, String ip) {
		for (String line : outputLines) {
			if (line.contains("unreachable")) { // IP address is not alive
				return false; // IP address was unreachable
			}
			
			synchronized (this) { // TODO was not here
				if (line.contains("TTL=")) { // IP address is alive
					aliveIpAddresses.add(ip); // add scanned IP to list if the IP is alive

//				if (line.contains("TTL=64")) { 
//					operatingSystem.add("Unix/Linux Variant"); // set OS to Linux variant if TTL is 64
//				} else

					if (line.contains("TTL=128")) {
						operatingSystem.add("Windows"); // set OS to windows if TTL is 128
					} else {
						operatingSystem.add(""); // set OS to unknown otherwise
					}

					macAddresses.add(getMacAdressByUseArp(ip)); // look up MAC address of IP address

					// initialize alive ports index for IP address
					aliveTcpPorts.add("");
					aliveUdpPorts.add("");

					return true; // IP address was reachable
				}
			}
		}
		return false; // IP address was unreachable
	}
	
	// use to partake in the pinging of IPs to check if they are alive
	private void isReachableByPing(String ip) {
		try {
			String command;

			// determine host OS to use required command
			if (System.getProperty("os.name").toLowerCase().startsWith("windows")) {
				command = "ping -n 2 " + ip; // for windows
			} else {
				command = "ping -c 2 " + ip; // for linux and osx
			}

			Process proc = Runtime.getRuntime().exec(command); // execute command
			
			// StreamGobbler class to parse executed command
			StreamGobbler outputGobbler = new StreamGobbler(proc.getInputStream(), "OUTPUT"); 
			outputGobbler.start(); 
			proc.waitFor();
			
			// send output to be validated if IP was reachable (ping)
			boolean valid = checkAvailability(outputGobbler.getOutputLines(), ip);
			
			// if IP was reached...
			if (valid) {
				populateTable(); // update the displaying table
			}
			
		} catch (IOException | InterruptedException ex) {
			JOptionPane.showMessageDialog(null, "Pinging IP error");
		}
	}
	
	// used to decrement the amount of IPs to be scanned
	private synchronized void getAnIP(String threadName) {
		if (amtUnscannedIP >= 0) {
			amtUnscannedIP--;
			amtScannedIP++;
		}
	}

	// used to get IP from within range to ping
	private void pingIP(String threadName) {
		String ip = ipAddressesInRange.get(0); // get an IP to ping
		ipAddressesInRange.remove(0); // remove IP that is ready to ping
		isReachableByPing(ip); // function to ping IP (check if IP is alive)
	}
	
		
	// function to get MAC address using IP
	private static String getMacAdressByUseArp(String ip) {
	    String command = "arp -a " + ip; // command to look up MAC address
	    Scanner scan = null;
	    String str = "";
	    
	    // pattern to compare MAC address
	    Pattern pattern = Pattern.compile("(([0-9A-Fa-f]{2}[-:]){5}[0-9A-Fa-f]{2})|(([0-9A-Fa-f]{4}\\.){2}[0-9A-Fa-f]{4})");
	    try {
	    	// store stream result from command execution
	    	scan = new Scanner(Runtime.getRuntime().exec(command).getInputStream());
	    	
	        while (scan.hasNext()) { // iterate through steam output
	            str = scan.next(); // get a stream
	            Matcher matcher = pattern.matcher(str); // compare stream with pattern
	            
	            if (matcher.matches()){
	                break; // break loop if MAC address was found
	            }
	            else{
	                str = "";
	            }
	        }
	    }
	    catch(IOException ioe) {
	    	JOptionPane.showMessageDialog(null, "getting mac address error");
	    }
	    finally {
	    	scan.close(); // garbage collection
	    }
	    
	    // return MAC address if string is not empty otherwise return empty string
	    return (str != "") ? str.toUpperCase().replace('-', ':'): "";
	}
	
	
	// validate if ports are ready to be scanned
	private void readyForPortScan(String portType) {
		DefaultTableModel tableModel = (DefaultTableModel) tableScanner.getModel();
		int rows = tableModel.getRowCount();
		
		// if table is not empty (rows)
		if (rows > 0) {
			
			// if ports to be scanned is TCP
			if (portType.equalsIgnoreCase("TCP")) { 
				resetForTcpScan(); // reset components before TCP scan
				readMultiplePorts("TCP"); // read ports from format in text field
				
				// if entry from text field was parsed from string to integer
				if (validatePortParsing("TCP")) {
					// if port range is valid and port is set to be scanned (scan flag)
					if (validatePortRange("TCP") && tcpScanFlag) {
						beginScanTcpPorts(); // begin the scan
					}
				}
			}

			// if ports to be scanned is UDP
			if (portType.equalsIgnoreCase("UDP")) {
				resetForUdpScan(); // reset components before UDP scan
				readMultiplePorts("UDP"); // read ports from format in text field
				
				// if entry from text field was parsed from string to integer
				if (validatePortParsing("UDP")) {
					// if port range is valid and port is set to be scanned (scan flag)
					if (validatePortRange("UDP") && udpScanFlag) {
						beginScanUdpPorts(); // begin the scan
					}
				}
			}
		}
	}
	
	
	// class to use multithreading to check IP's that are alive
	class IpPing extends Thread {
		
		private Thread thread;
		private String threadName;
		
		IpPing(String name) {
			threadName = name;
		}
		
		public void run() {
			// while true and thread is not indicated to stop threads
			while (true && !stopThreads) {
				try {
					Thread.sleep((int) (Math.random() * 5000));
				} catch (InterruptedException e) {
					JOptionPane.showMessageDialog(null, "Ping thread error");
				}
				
				// if IP address is available for scanning
				if (amtUnscannedIP >= 0) {
					getAnIP(threadName); // get an IP address
					pingIP(threadName); // ping the IP address
					
					if (!ipScanEnded)
						showProgress(amtScannedIP); // update progress bar
				}
				else
					break;	// break when there is no more IP to scan
			}
			
			if (ipScanEnded == false) {
				ipScanEnded = true; // indicate that scan has ended
				
				// wait for other threads to stop sanning
				try {
					TimeUnit.SECONDS.sleep(8);
				} catch (InterruptedException e) {
					e.printStackTrace();
				}
				
				if (!stopThreads) {
					// set display for task label if threads were not manually stopped
					lblOngoingTask.setText("Finished Scanning Ip's...");
					progressBar.setValue(100);
				}
				
				changeStateOfButtons(true); // enable buttons after scanning is finished
				
			}		
		}
		
		// start threads
		public void start() {
			if (thread == null) {
				thread = new Thread(this, threadName);
				thread.start();
			}
		}
	}
	/** IP Scanning ------ End */
	
	
	
	
	
	
	
	
	
	
	
	/** TCP Scanning ------ Start */

	// begin the scanning process of TCP ports
	private void beginScanTcpPorts() {
		
		// set task label that TCP ports are being scanned
		lblOngoingTask.setText("Scanning TCP Ports...");
		
		changeStateOfButtons(false);// disable buttons while scanning
		
		setTcpPortsInRange(); // function to set array of TCP in specified range to scan

		int threads = 0; // amount of threads to create for scanning TCP
		
		// use max specified threads if amount to be scanned is equivalent or greater
		if (amtUnscannedTCP >= maxTcpThread) 
			amtTcpThreads = threads = maxTcpThread;
		else
			amtTcpThreads = threads = amtUnscannedTCP;
		
		// create array of TCP class
		TCP[] tcp = new TCP[threads];
		
		// initialize array
		for (int i = 0; i < threads; i++) {
			tcp[i] = new TCP((Integer.toString(i))); // pass iterative # to be used as thread name
		}
					
		// start the array of thread
		for (int i = 0; i < threads; i++) {
			tcp[i].start();
		}
	}
	
	// set ports in range to be scanned
	private synchronized void setTcpPortsInRange() {
		amtUnscannedTCP = endTcpPort - startTcpPort; // the amount of TCP ports to be scanned
		
		// formula for progress bar when scanning TCP ports
		progressBarFormula = ((double) progressBarMaxPercentage) /  (((double) amtUnscannedTCP * (double) aliveIpAddresses.size())); 
		tcpPortsInRange.clear(); // clear ports in range
		int startPort = startTcpPort; // set starting port
		
		// the amount of ports to be scanned
		for (int i = 0; i <= amtUnscannedTCP; i++) {
			tcpPortsInRange.add(startPort); // add TCP port to be scanned
			startPort++;
		}
	}
	
	// increment index for rows (IP addresses in table)
	private synchronized void incrIndexForTcp() {
//		if (amtUnscannedTCP < 0) { // if no ports are left to scan at current index
			indexForIpTCP++; 
			setTcpPortsInRange(); // function to set ports in range to be scanned
			endedTCP = 0;
//		}
	}
		
	
	// used to decrement the amount of TCP ports remaining to be scanned
	private synchronized void getTcpPort(String threadName) {
		if (amtUnscannedTCP >= 0) {
			amtUnscannedTCP--;
			amtScannedTCP++; // count the amount of ports scanned
		}
	}
	
	// remove TCP port from list of range to be scanned
	private synchronized int removeTcpPort() {
		if (tcpPortsInRange.size() == 0)
			return -1;
		
		int port = tcpPortsInRange.get(0);
    	tcpPortsInRange.remove(0); // remove port
    	return port;
	}
	
	// function to scan TCP port
	private void scanTcpPort(String ip, int index) {
		// ** index is use to access corresponding index of alive TCP
		// port array list to the IP address
		try {
			InetAddress inetAddress = InetAddress.getByName(ip);
			String hostName = inetAddress.getHostName();
			
            try {
            	if (tcpPortsInRange.size() == 0) {
            		return;
            	}
            	
            	int port;
            	
            	synchronized (this) {
            		port = removeTcpPort(); // get port to be scanned
            	}
            	
            	if (port == -1)
            		return;
            		
                Socket socket = new Socket(hostName, port); // check port using TCP connection
                
                // if no previous ports was stored
                if (aliveTcpPorts.get(index).equalsIgnoreCase("")) {
                	aliveTcpPorts.set(index, (aliveTcpPorts.get(index) + port));
                } else { // if previous ports was found, then separate with a comma
                	String[] tcpSegment = aliveTcpPorts.get(index).split("\\,");
                	boolean found = false;
                	
                	for (String s : tcpSegment) {
                		if(s.trim().equalsIgnoreCase(Integer.toString(port))) {
                			found = true;
                			break;
                		}
                	}
                	
                	if (!found) {
                		aliveTcpPorts.set(index, (aliveTcpPorts.get(index) + ", " + port));
                	}
                	
//                	aliveTcpPorts.set(index, (aliveTcpPorts.get(index) + ", " + port));
                }

                socket.close(); 
                
                populateTable(); // update table display
                
            } catch (IOException ioe) {
            	crashedTCP++;
            	return;
            }
		} catch (UnknownHostException uhe) {
			crashedTCP++;
        	return;
		}
	}
	
	// class to use multithreading to check TCP ports that are alive
	class TCP extends Thread {

		private Thread thread;
		private String threadName;

		TCP(String name) {
			threadName = name;
		}

		public void run() {

			// while true and thread is not indicated to stop threads
			while (true && !stopThreads) {
				
				// TODO test output to analyze thread hogging...
				
				try {
					Thread.sleep((int) (Math.random() * 10000));
				} catch (InterruptedException e) {
					JOptionPane.showMessageDialog(null, "TCP thread error");
				}

				// if TCP ports to be scan are depleted for current index
				if (tcpPortsInRange.size() == 0) {
					// if index for IP (row) from table is less than the available addresses
					if (indexForIpTCP < (aliveIpAddresses.size() - 1)) {
						synchronized (this) {
							if ((endedTCP + crashedTCP) >= amtTcpThreads) {
								incrIndexForTcp(); // increment index
							}
						}
					}
					// break loop if index has reached the total available addresses
					else if (indexForIpTCP == (aliveIpAddresses.size() - 1)) {
						break;
					}
				}
				
				// if TCP ports are available to be scanned using 0 boundary value
				else if (amtUnscannedTCP >= -1) {
					if (tcpPortsInRange.size() != 0) { // if TCP ports are available
						getTcpPort(threadName); // get a port to be scanned
						
						// scan port, passing IP address and index as parameter
						scanTcpPort(aliveIpAddresses.get(indexForIpTCP), indexForIpTCP);
						endedTCP++; // count ended scans
						
						if (!tcpScanEnded)
							showProgress(amtScannedTCP); // update progress bar
					}
				} 
				
				// if TCP ports are depleted
				else if (amtUnscannedTCP <= 0) {
					// if no more index remain (currently at the last index)
					if (indexForIpTCP == (aliveIpAddresses.size() - 1)) {
						break; // break loop
					}
				}

			}

			if (tcpScanEnded == false) {
				tcpScanEnded = true; // indicate that scan has ended
				
				// wait for other threads to stop scanning
				try {
					TimeUnit.SECONDS.sleep(8);
				} catch (InterruptedException e) {
					e.printStackTrace();
				}
				
				if (!stopThreads) {
					// set display for task label if threads were not manually stopped
					lblOngoingTask.setText("Finished Scanning TCP Ports...");
					progressBar.setValue(100);
				}
				
				changeStateOfButtons(true); // enable buttons after scanning is finished
			}
		}

		// start threads
		public void start() {
			if (thread == null) {
				thread = new Thread(this, threadName);
				thread.start();
			}
		}
	}
	/** TCP Scanning ------ End */
	
	
	
	
	
	
	
	
	/** UDP Scanning ------ Start */
	
	// begin the scanning process of TCP ports
	private void beginScanUdpPorts() {
		
		// set task label that TCP ports are being scanned
		lblOngoingTask.setText("Scanning UDP Ports...");
		
		changeStateOfButtons(false);// disable buttons while scanning
		setUdpPortsInRange(); // function to set array of UDP in specified range to scan

		int threads = 0; // amount of threads to create for scanning UDP
		
		// use max specified threads if amount to be scanned is equivalent or greater
		if (amtUnscannedUDP >= maxUdpThread) 
			amtUdpThreads = threads = maxUdpThread;
		else
			amtUdpThreads = threads = amtUnscannedUDP;
		
		// create array of UDP class
		UDP[] udp = new UDP[threads];
		
		// use max specified threads if amount to be scanned is equivalent or greater
		for (int i = 0; i < threads; i++) {
			udp[i] = new UDP((Integer.toString(i))); // pass iterative # to be used as thread name
		}
					
		// start the array of thread
		for (int i = 0; i < threads; i++) {
			udp[i].start();
		}
	}
	
	// set UDP ports in range to be scanned
	private synchronized void setUdpPortsInRange() {
		amtUnscannedUDP = endUdpPort - startUdpPort; // the amount of UDP ports to be scanned
		
		// formula for progress bar when scanning UDP ports
		progressBarFormula = ((double) progressBarMaxPercentage) /  (((double) amtUnscannedUDP * (double) aliveIpAddresses.size()));
		udpPortsInRange.clear(); // clear ports in range
		int startPort = startUdpPort; // set starting port
		
		for (int i = 0; i <= amtUnscannedUDP; i++) { // the amount of ports to be scanned
			udpPortsInRange.add(startPort); // add UDP port to be scanned
			startPort++;
		}
	}
	
	// increment index for rows (IP addresses in table)
	private synchronized void incrIndexForUdp() { // if no ports are left to scan at current index
		if (amtUnscannedUDP < 0) {
			indexForIpUDP++;
			setUdpPortsInRange(); // function to set ports in range to be scanned
			endedUDP = 0;
		}
	}
	
	// used to decrement the amount of IPs to be scanned
	private synchronized void getUdpPort(String threadName) {
		if (amtUnscannedUDP >= 0) {
			amtUnscannedUDP--;
			amtScannedUDP++;
		}
	}
	
	// remove UDP port from list of range to be scanned
	private synchronized int removeUdpPort() {
		int port = udpPortsInRange.get(0);
    	udpPortsInRange.remove(0); // remove port
    	return port;
	}
	
	// TODO UDP PORT SCANNING
	// function to scan UDP port
	private void scanUdpPort(String ip, int index) {
		// ** index is use to access corresponding index of alive UDP
		// port array list to the IP address
		
	    int port = removeUdpPort(); // get port to be scanned
	    
	    // check ports using UDP connection
		try {
	    	InetAddress inetAddress = InetAddress.getByName(ip);
	
	    	byte [] bytes = new byte[128];
	        DatagramSocket ds = new DatagramSocket();
	        DatagramPacket dp = new DatagramPacket(bytes, bytes.length); 
	        ds.setSoTimeout(1000);
	        ds.connect(inetAddress, port); 
	        ds.send(dp);
	        ds.isConnected(); 
	        dp = new DatagramPacket(bytes, bytes.length);
	        ds.receive(dp);
	        ds.close();
	    }
		catch (SocketTimeoutException se) {
			// breaks from scanning UDP port if OS is not windows
		    if (!operatingSystem.get(index).equalsIgnoreCase("WINDOWS"))
				return;
						
			// if no previous ports was stored
			if (aliveUdpPorts.get(index).equalsIgnoreCase("")) {
				aliveUdpPorts.set(index, (aliveUdpPorts.get(index) + port));
			} else { // if previous ports was found, then separate with a comma
				aliveUdpPorts.set(index, (aliveUdpPorts.get(index) + ", " + port));
			}
			populateTable(); // update table display
		}
	    catch(IOException e){
	    	return; // UDP port was closed
	    }
	}
	
	// class to use multithreading to check UDP ports that are alive
	class UDP extends Thread {

		private Thread thread;
		private String threadName;

		UDP(String name) {
			threadName = name;
		}

		public void run() {

			// while true and thread is not indicated to stop threads
			while (true && !stopThreads) {
				try {
					Thread.sleep((int) (Math.random() * 10000));
				} catch (InterruptedException e) {
					JOptionPane.showMessageDialog(null, "UDP thread error");
				}
				
				// if UDP ports to be scan are depleted for current index
				if (amtUnscannedUDP < 0) {
					// if index for IP (row) from table is less than the available addresses
					if (indexForIpUDP < (aliveIpAddresses.size() - 1)) { 
						synchronized (this) {
							if (endedUDP >= amtUdpThreads) {
								incrIndexForUdp(); // increment index
							}
						}
					}
					// break loop if index has reached the total available addresses
					else if (indexForIpUDP == (aliveIpAddresses.size() - 1)) {
						break; // break loop
						
					}
				}
				
				// if UDP ports are available to be scanned using 0 boundary value
				else if (amtUnscannedUDP >= 0) {
					if (udpPortsInRange.size() != 0) { // if UDP ports are available
						getUdpPort(threadName); // get a port to be scanned
						
						// scan port, passing IP address and index as parameter
						scanUdpPort(aliveIpAddresses.get(indexForIpUDP), indexForIpUDP);
						endedUDP++; // count ended scans
						
						if(!udpScanEnded)
							showProgress(amtScannedUDP); // update progress bar
					}
				} 
				
				// if UDP ports are depleted
				else if (amtUnscannedUDP <= 0) {
					// if no more index remain (currently at the last index)
					if (indexForIpUDP == (aliveIpAddresses.size() - 1)) {
						break; // break loop
					}
				}
			}

			if (udpScanEnded == false) {
				udpScanEnded = true; // indicate that scan has ended

				// wait for other threads to stop scanning
				try {
					TimeUnit.SECONDS.sleep(8);
				} catch (InterruptedException e) {
					e.printStackTrace();
				}
				
				if (!stopThreads) {
					// set display for task label if threads were not manually stopped
					lblOngoingTask.setText("Finished Scanning UDP Ports...");
					progressBar.setValue(100);
				}
				
				changeStateOfButtons(true); // enable buttons after scanning is finished
			}
		}

		// start threads
		public void start() {
			if (thread == null) {
				thread = new Thread(this, threadName);
				thread.start();
			}
		}
	}
}










//TODO hostname thread

	/** HostName Lookup ------ Start */
	
	// begin the scanning process of TCP ports

	/*
	private void beginHostNameLookUp() {

		// set task label that TCP ports are being scanned
		lblOngoingTask.setText("Looking Up Hostname...");

		changeStateOfButtons(false);// disable buttons while scanning
		setUdpPortsInRange(); // function to set array of UDP in specified range to scan

		int threads = 0; // amount of threads to create for scanning UDP

		// use max specified threads if amount to be scanned is equivalent or greater
		if (amtUnscannedUDP >= maxUdpThread)
			amtUdpThreads = threads = maxUdpThread;
		else
			amtUdpThreads = threads = amtUnscannedUDP;

		// create array of UDP class
		HostNameLookUp[] hostNameLookUp = new HostNameLookUp[threads];

		// use max specified threads if amount to be scanned is equivalent or greater
		for (int i = 0; i < threads; i++) {
			hostNameLookUp[i] = new HostNameLookUp((Integer.toString(i))); // pass iterative # to be used as thread name
		}

		// start the array of thread
		for (int i = 0; i < threads; i++) {
			hostNameLookUp[i].start();
		}
	}
	
	// set UDP ports in range to be scanned
	private synchronized void setAliveHostToLookUp() {
		amtUnscannedUDP = endUdpPort - startUdpPort; // the amount of UDP ports to be scanned

		// formula for progress bar when scanning UDP ports
		progressBarFormula = ((double) progressBarMaxPercentage)
				/ (((double) amtUnscannedUDP * (double) aliveIpAddresses.size()));
		udpPortsInRange.clear(); // clear ports in range
		int startPort = startUdpPort; // set starting port

		for (int i = 0; i <= amtUnscannedUDP; i++) { // the amount of ports to be scanned
			udpPortsInRange.add(startPort); // add UDP port to be scanned
			startPort++;
		}
	}
	
	
	class HostNameLookUp extends Thread {

		private Thread thread;
		private String threadName;

		HostNameLookUp(String name) {
			threadName = name;
		}

		public void run() {

			// while true and thread is not indicated to stop threads
			while (true && !stopThreads) {
				try {
					Thread.sleep((int) (Math.random() * 5000));
				} catch (InterruptedException e) {
					JOptionPane.showMessageDialog(null, "HostName Lookup thread error");
				}
				
				// if UDP ports to be scan are depleted for current index
				if (amtUnscannedUDP < 0) {
					// if index for IP (row) from table is less than the available addresses
					if (indexForIpUDP < (aliveIpAddresses.size() - 1)) { 
						synchronized (this) {
							if (endedUDP >= amtUdpThreads) {
								incrIndexForUdp(); // increment index
							}
						}
					}
					// break loop if index has reached the total available addresses
					else if (indexForIpUDP == (aliveIpAddresses.size() - 1)) {
						break; // break loop
						
					}
				}
				
				// if UDP ports are available to be scanned using 0 boundary value
				else if (amtUnscannedUDP >= 0) {
					if (udpPortsInRange.size() != 0) { // if UDP ports are available
						getUdpPort(threadName); // get a port to be scanned
						
						// scan port, passing IP address and index as parameter
						scanUdpPort(aliveIpAddresses.get(indexForIpUDP), indexForIpUDP);
						endedUDP++; // count ended scans
						
						if(!udpScanEnded)
							showProgress(amtScannedUDP); // update progress bar
					}
				} 
				
				// if UDP ports are depleted
				else if (amtUnscannedUDP <= 0) {
					// if no more index remain (currently at the last index)
					if (indexForIpUDP == (aliveIpAddresses.size() - 1)) {
						break; // break loop
					}
				}
			}

			if (udpScanEnded == false) {
				udpScanEnded = true; // indicate that scan has ended

				// wait for other threads to stop scanning
				try {
					TimeUnit.SECONDS.sleep(8);
				} catch (InterruptedException e) {
					e.printStackTrace();
				}
				
				if (!stopThreads) {
					// set display for task label if threads were not manually stopped
					lblOngoingTask.setText("Finished Scanning UDP Ports...");
					progressBar.setValue(100);
				}
				
				changeStateOfButtons(true); // enable buttons after scanning is finished
			}
		}

		// start threads
		public void start() {
			if (thread == null) {
				thread = new Thread(this, threadName);
				thread.start();
			}
		}
	}
	*/
