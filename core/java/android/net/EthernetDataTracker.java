/*
 * Copyright (C) 2010 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package android.net;

import android.content.Context;
import android.net.LinkAddress;
import android.net.RouteInfo;
import android.net.ethernet.EthernetDevInfo;
import android.net.ethernet.EthernetManager;
import android.net.NetworkInfo.DetailedState;
import android.os.Handler;
import android.os.IBinder;
import android.os.INetworkManagementService;
import android.os.Message;
import android.os.Messenger;
import android.os.RemoteException;
import android.os.ServiceManager;
import android.util.Log;
import android.content.Intent;

import java.net.InetAddress;
import java.net.Inet4Address;

import com.android.server.net.BaseNetworkObserver;

import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * This class tracks the data connection associated with Ethernet
 * This is a singleton class and an instance will be created by
 * ConnectivityService.
 * @hide
 */
public class EthernetDataTracker extends BaseNetworkStateTracker {
    public static final int ETHERNET_CONNECTED = 1;
    public static final int ETHERNET_DISCONNECTED = 2;
    private static final String NETWORKTYPE = "ETHERNET";
    private static final String TAG = "Ethernet";

    private AtomicBoolean mTeardownRequested = new AtomicBoolean(false);
    private AtomicBoolean mPrivateDnsRouteSet = new AtomicBoolean(false);
    private AtomicInteger mDefaultGatewayAddr = new AtomicInteger(0);
    private AtomicBoolean mDefaultRouteSet = new AtomicBoolean(false);

    private static boolean mEnabled = false;
    private static boolean mLinkUp;
    private InterfaceObserver mInterfaceObserver;
    private String mHwAddr;
    private EthernetDevInfo mDevInfo;

    /* For sending events to connectivity service handler */
    private Handler mCsHandler;

    private static EthernetDataTracker sInstance;
    private static String sIfaceMatch = "";
    private static String mIface = "";

    private INetworkManagementService mNMService;

    private static class InterfaceObserver extends BaseNetworkObserver {
        private EthernetDataTracker mTracker;

        InterfaceObserver(EthernetDataTracker tracker) {
            super();
            mTracker = tracker;
        }

        @Override
        public void interfaceStatusChanged(String iface, boolean up) {
            Log.d(TAG, "Interface status changed: " + iface + (up ? "up" : "down"));
        }

        @Override
        public void interfaceLinkStateChanged(String iface, boolean up) {
            if (mIface.equals(iface)) {
                Log.d(TAG, "Interface " + iface + " link " + (up ? "up" : "down"));
                mLinkUp = up;
                if (mEnabled == false)
                    return;
                mTracker.mNetworkInfo.setIsAvailable(up);

                // use DHCP
                if (up) {
                    mTracker.reconnect();
                } else {
                    mTracker.disconnect();
                    mTracker.sendStateBroadcast(EthernetManager.EVENT_DISCONNECTED);
                }
            }
        }

        @Override
        public void interfaceAdded(String iface) {
            mTracker.interfaceAdded(iface);
        }

        @Override
        public void interfaceRemoved(String iface) {
            mTracker.interfaceRemoved(iface);
        }
    }

    private EthernetDataTracker() {
        mNetworkInfo = new NetworkInfo(ConnectivityManager.TYPE_ETHERNET, 0, NETWORKTYPE, "");
        mLinkProperties = new LinkProperties();
        mLinkCapabilities = new LinkCapabilities();
        mDevInfo = null;
    }

    //send broadcast to update ethernet icon
    private void sendBroadcast() {
    }

    private void sendStateBroadcast(int event) {
        Intent intent = new Intent(EthernetManager.NETWORK_STATE_CHANGED_ACTION);
        intent.addFlags(Intent.FLAG_RECEIVER_REGISTERED_ONLY_BEFORE_BOOT
									| Intent.FLAG_RECEIVER_REPLACE_PENDING);
        intent.putExtra(EthernetManager.EXTRA_NETWORK_INFO, mNetworkInfo);
        intent.putExtra(EthernetManager.EXTRA_LINK_PROPERTIES,
							new LinkProperties (mLinkProperties));
		intent.putExtra(EthernetManager.EXTRA_ETHERNET_STATE, event);
        mContext.sendStickyBroadcast(intent);
    }

    private void interfaceAdded(String iface) {
        if (!iface.matches(sIfaceMatch))
            return;

        Log.d(TAG, "Adding " + iface);

        synchronized(this) {
            if(!mIface.isEmpty())
                return;
            mIface = iface;
        }

        // we don't get link status indications unless the iface is up - bring it up
        try {
            mNMService.setInterfaceUp(iface);
        } catch (Exception e) {
            Log.e(TAG, "Error upping interface " + iface + ": " + e);
        }

        mNetworkInfo.setIsAvailable(true);
        Message msg = mCsHandler.obtainMessage(EVENT_CONFIGURATION_CHANGED, mNetworkInfo);
        msg.sendToTarget();
    }

    public void disconnect() {
	    if (mEnabled == false && !mLinkUp)
	        return;
		
		Log.d(TAG, "disconnect tracker");
	
        NetworkUtils.stopDhcp(mIface);

        mLinkProperties.clear();
        mNetworkInfo.setIsAvailable(false);
        mNetworkInfo.setDetailedState(DetailedState.DISCONNECTED, null, mHwAddr);

        Message msg = mCsHandler.obtainMessage(EVENT_CONFIGURATION_CHANGED, mNetworkInfo);
        msg.sendToTarget();

        msg = mCsHandler.obtainMessage(EVENT_STATE_CHANGED, mNetworkInfo);
        msg.sendToTarget();

        IBinder b = ServiceManager.getService(Context.NETWORKMANAGEMENT_SERVICE);
        INetworkManagementService service = INetworkManagementService.Stub.asInterface(b);
        try {
            service.clearInterfaceAddresses(mIface);
        } catch (Exception e) {
            Log.e(TAG, "Failed to clear addresses or disable ipv6" + e);
        }
        sendStateBroadcast(EthernetManager.EVENT_DISCONNECTED);
    }

    private void interfaceRemoved(String iface) {
        if (!iface.equals(mIface))
            return;

        Log.d(TAG, "Removing " + iface);
        disconnect();
        mIface = "";
    }

    private void runDhcp() {
        Thread dhcpThread = new Thread(new Runnable() {
            public void run() {
                DhcpResults dhcpResults = new DhcpResults();
                if (!NetworkUtils.runDhcp(mIface, dhcpResults)) {
                    Log.e(TAG, "DHCP request error:" + NetworkUtils.getDhcpError());
                    sendStateBroadcast(EthernetManager.EVENT_CONFIGURATION_FAILED);
                    return;
                }
                mLinkProperties = dhcpResults.linkProperties;

                mNetworkInfo.setIsAvailable(true);
                mNetworkInfo.setDetailedState(DetailedState.CONNECTED, null, mHwAddr);
                Message msg = mCsHandler.obtainMessage(EVENT_STATE_CHANGED, mNetworkInfo);
                msg.sendToTarget();
                sendStateBroadcast(EthernetManager.EVENT_CONFIGURATION_SUCCEEDED);
            }
        });
	    try {
            mNMService.clearInterfaceAddresses(mIface);
        } catch (Exception e) {
            Log.e(TAG, "Failed to clear addresses" + e);
        }
	    dhcpThread.start();
    }

     /**
     * Set up the manual configuration 
     * - IP address
     * - Netmask
     * - Default route
     * - Dns Servers (EthernetDevInfo needs update to provide second serveur)
     */
    private void setManualConf() {
        try {
	    	// Cleaning up
	    	mNMService.clearInterfaceAddresses(mIface);
	    	mLinkProperties.clear();
	    	// Ip Address and mask
	    	InterfaceConfiguration config = mNMService.getInterfaceConfig(mIface);
	    	InetAddress addr = NetworkUtils.numericToInetAddress(mDevInfo.getIpAddress());
	    	int prefix_length = NetworkUtils.netmaskIntToPrefixLength(NetworkUtils.inetAddressToInt
	        				((Inet4Address)NetworkUtils.numericToInetAddress(mDevInfo.getNetMask())));
	    	config.setLinkAddress(new LinkAddress(addr, prefix_length)); 
	    	Log.d(TAG, "setManualConf : set config");
	    	mNMService.setInterfaceConfig(mIface, config);
		} catch (Exception e) {
            Log.e(TAG, "Failed to set manual configuration" + e);
            sendStateBroadcast(EthernetManager.EVENT_CONFIGURATION_FAILED);
	    	return;
        }
	
		// Set LinkProperties.
		mLinkProperties.setInterfaceName(mIface);
		mLinkProperties.addLinkAddress(new LinkAddress(NetworkUtils.numericToInetAddress(mDevInfo.getIpAddress()), 
					    NetworkUtils.netmaskIntToPrefixLength(NetworkUtils.inetAddressToInt
					    ((Inet4Address)NetworkUtils.numericToInetAddress(mDevInfo.getNetMask())))));
		String dns[] = mDevInfo.getDnsAddr();
		mLinkProperties.addDns(NetworkUtils.numericToInetAddress(dns[0]));
		mLinkProperties.addDns(NetworkUtils.numericToInetAddress(dns[1]));
		mLinkProperties.addRoute(new RouteInfo(null, NetworkUtils.numericToInetAddress(mDevInfo.getGateWay())));

		mNetworkInfo.setDetailedState(DetailedState.CONNECTED, null, mHwAddr);
		Message msg = mCsHandler.obtainMessage(EVENT_STATE_CHANGED, mNetworkInfo);
		msg.sendToTarget();
		sendStateBroadcast(EthernetManager.EVENT_CONFIGURATION_SUCCEEDED);
    }

    /**
     * Set up the IP configuration, either start dhcp or
     * apply static configuration.
     */
    private void setUpIPConfig() {
		if (mDevInfo == null) {
		    Log.e(TAG, "setUpIPConfig Error : No mDevInfo");
		    return; 
		}
		if (mDevInfo.getConnectMode() == EthernetDevInfo.ETHERNET_CONN_MODE_DHCP) {
	    	Log.d(TAG, "setUpIPConfig : Using DHCP");
	    	runDhcp();
		}
		else if (mDevInfo.getConnectMode() == EthernetDevInfo.ETHERNET_CONN_MODE_MANUAL) {
	    	Log.d(TAG, "setUpIPConfig : Using manual configuration");
	    	setManualConf();
		}
		else {
	    	Log.e(TAG, "setUpIPConfig Error : Wrong connection mode : " + mDevInfo.getConnectMode());
	    	return;
		}
    }


    public static synchronized EthernetDataTracker getInstance() {
        if (sInstance == null) sInstance = new EthernetDataTracker();
        return sInstance;
    }

    public Object Clone() throws CloneNotSupportedException {
        throw new CloneNotSupportedException();
    }

    public void setTeardownRequested(boolean isRequested) {
        mTeardownRequested.set(isRequested);
    }

    public boolean isTeardownRequested() {
    	//sendStateBroadcast(EthernetManager.EVENT_DISCONNECTED);
        return mTeardownRequested.get();
    }

    /**
     * Begin monitoring connectivity
     */
    public void startMonitoring(Context context, Handler target) {
        mContext = context;
        mCsHandler = target;

        // register for notifications from NetworkManagement Service
        IBinder b = ServiceManager.getService(Context.NETWORKMANAGEMENT_SERVICE);
        mNMService = INetworkManagementService.Stub.asInterface(b);

        mInterfaceObserver = new InterfaceObserver(this);

        // enable and try to connect to an ethernet interface that
        // already exists
        sIfaceMatch = context.getResources().getString(
            com.android.internal.R.string.config_ethernet_iface_regex);
        try {
            final String[] ifaces = mNMService.listInterfaces();
            for (String iface : ifaces) {
                if (iface.matches(sIfaceMatch)) {
                    mIface = iface;
                    mNMService.setInterfaceUp(iface);
                    InterfaceConfiguration config = mNMService.getInterfaceConfig(iface);
                    mLinkUp = config.hasFlag("up");
                    if (config != null && mHwAddr == null) {
                        mHwAddr = config.getHardwareAddress();
                        if (mHwAddr != null) {
                            mNetworkInfo.setExtraInfo(mHwAddr);
                        }
                    }

                    // if a DHCP client had previously been started for this interface, then stop it
                    NetworkUtils.stopDhcp(mIface);

                    reconnect();
                    break;
                }
            }
        } catch (RemoteException e) {
            Log.e(TAG, "Could not get list of interfaces " + e);
        }

        try {
            mNMService.registerObserver(mInterfaceObserver);
        } catch (RemoteException e) {
            Log.e(TAG, "Could not register InterfaceObserver " + e);
        }
    }

    /**
     * Disable connectivity to a network
     * TODO: do away with return value after making MobileDataStateTracker async
     */
    public boolean teardown() {
	    if (mEnabled == false)
	        return false;
        mTeardownRequested.set(true);
        NetworkUtils.stopDhcp(mIface);
        return true;
    }

    /**
     * Re-enable connectivity to a network after a {@link #teardown()}.
     */
    public boolean reconnect() {
		if (mEnabled == true && mLinkUp) {
            mTeardownRequested.set(false);
            setUpIPConfig();
        }
        return mLinkUp;
    }

    @Override
    public void captivePortalCheckComplete() {
        // not implemented
    }

    @Override
    public void captivePortalCheckCompleted(boolean isCaptivePortal) {
        // not implemented
    }

    /**
     * Turn the wireless radio off for a network.
     * @param turnOn {@code true} to turn the radio on, {@code false}
     */
    public boolean setRadio(boolean turnOn) {
        return true;
    }

    /**
     * @return true - If are we currently tethered with another device.
     */
    public synchronized boolean isAvailable() {
        return mNetworkInfo.isAvailable();
    }

    /**
     * Tells the underlying networking system that the caller wants to
     * begin using the named feature. The interpretation of {@code feature}
     * is completely up to each networking implementation.
     * @param feature the name of the feature to be used
     * @param callingPid the process ID of the process that is issuing this request
     * @param callingUid the user ID of the process that is issuing this request
     * @return an integer value representing the outcome of the request.
     * The interpretation of this value is specific to each networking
     * implementation+feature combination, except that the value {@code -1}
     * always indicates failure.
     * TODO: needs to go away
     */
    public int startUsingNetworkFeature(String feature, int callingPid, int callingUid) {
        return -1;
    }

    /**
     * Tells the underlying networking system that the caller is finished
     * using the named feature. The interpretation of {@code feature}
     * is completely up to each networking implementation.
     * @param feature the name of the feature that is no longer needed.
     * @param callingPid the process ID of the process that is issuing this request
     * @param callingUid the user ID of the process that is issuing this request
     * @return an integer value representing the outcome of the request.
     * The interpretation of this value is specific to each networking
     * implementation+feature combination, except that the value {@code -1}
     * always indicates failure.
     * TODO: needs to go away
     */
    public int stopUsingNetworkFeature(String feature, int callingPid, int callingUid) {
        return -1;
    }

    @Override
    public void setUserDataEnable(boolean enabled) {
        Log.w(TAG, "ignoring setUserDataEnable(" + enabled + ")");
    }

    @Override
    public void setPolicyDataEnable(boolean enabled) {
        Log.w(TAG, "ignoring setPolicyDataEnable(" + enabled + ")");
    }

    /**
     * Check if private DNS route is set for the network
     */
    public boolean isPrivateDnsRouteSet() {
        return mPrivateDnsRouteSet.get();
    }

    /**
     * Set a flag indicating private DNS route is set
     */
    public void privateDnsRouteSet(boolean enabled) {
        mPrivateDnsRouteSet.set(enabled);
    }

    /**
     * Fetch NetworkInfo for the network
     */
    public synchronized NetworkInfo getNetworkInfo() {
        return mNetworkInfo;
    }

    /**
     * Fetch LinkProperties for the network
     */
    public synchronized LinkProperties getLinkProperties() {
        return new LinkProperties(mLinkProperties);
    }

   /**
     * A capability is an Integer/String pair, the capabilities
     * are defined in the class LinkSocket#Key.
     *
     * @return a copy of this connections capabilities, may be empty but never null.
     */
    public LinkCapabilities getLinkCapabilities() {
        return new LinkCapabilities(mLinkCapabilities);
    }

    /**
     * Fetch default gateway address for the network
     */
    public int getDefaultGatewayAddr() {
        return mDefaultGatewayAddr.get();
    }

    /**
     * Check if default route is set
     */
    public boolean isDefaultRouteSet() {
        return mDefaultRouteSet.get();
    }

    /**
     * Set a flag indicating default route is set for the network
     */
    public void defaultRouteSet(boolean enabled) {
        mDefaultRouteSet.set(enabled);
    }

    /**
     * Return the system properties name associated with the tcp buffer sizes
     * for this network.
     */
    public String getTcpBufferSizesPropName() {
        return "net.tcp.buffersize.wifi";
    }

    public void setDependencyMet(boolean met) {
        // not supported on this network
    }

    /**
     * Update the network configuration.
     * It does not aftect the ongoing connection.
     */
    public void setDevConfiguration(EthernetDevInfo info) {
	mDevInfo = info;
    }

    public void setEnabled(boolean enabled) {
	mEnabled = enabled;
    }

    public boolean isEnabled() {
	return mEnabled;
    }

    @Override
    public void addStackedLink(LinkProperties link) {
        mLinkProperties.addStackedLink(link);
    }

    @Override
    public void removeStackedLink(LinkProperties link) {
        mLinkProperties.removeStackedLink(link);
    }

    @Override
    public void supplyMessenger(Messenger messenger) {
        // not supported on this network
    }
}
