/*******************************************************************************
 *                                                                             *
 *  Copyright (C) 2017 by Max Lv <max.c.lv@gmail.com>                          *
 *  Copyright (C) 2017 by Mygod Studio <contact-shadowsocks-android@mygod.be>  *
 *                                                                             *
 *  This program is free software: you can redistribute it and/or modify       *
 *  it under the terms of the GNU General Public License as published by       *
 *  the Free Software Foundation, either version 3 of the License, or          *
 *  (at your option) any later version.                                        *
 *                                                                             *
 *  This program is distributed in the hope that it will be useful,            *
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of             *
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the              *
 *  GNU General Public License for more details.                               *
 *                                                                             *
 *  You should have received a copy of the GNU General Public License          *
 *  along with this program. If not, see <http://www.gnu.org/licenses/>.       *
 *                                                                             *
 *******************************************************************************/

package com.github.shadowsocks

import android.app.Activity
import android.app.AlertDialog
import android.app.backup.BackupManager
import android.content.ActivityNotFoundException
import android.content.Intent
import android.graphics.Color
import android.net.VpnService
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.os.Message
import android.os.RemoteException
import android.util.Log
import android.view.KeyCharacterMap
import android.view.KeyEvent
import android.view.MenuItem
import android.view.View
import android.view.ViewGroup
import android.widget.EditText
import android.widget.FrameLayout
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.browser.customtabs.CustomTabColorSchemeParams
import androidx.browser.customtabs.CustomTabsIntent
import androidx.coordinatorlayout.widget.CoordinatorLayout
import androidx.core.content.ContextCompat
import androidx.core.net.toUri
import androidx.core.view.GravityCompat
import androidx.core.view.updateLayoutParams
import androidx.drawerlayout.widget.DrawerLayout
import androidx.preference.PreferenceDataStore
import com.crashlytics.android.Crashlytics
import com.github.shadowsocks.acl.CustomRulesFragment
import com.github.shadowsocks.aidl.IShadowsocksService
import com.github.shadowsocks.aidl.ShadowsocksConnection
import com.github.shadowsocks.aidl.TrafficStats
import com.github.shadowsocks.bg.BaseService
import com.github.shadowsocks.preference.DataStore
import com.github.shadowsocks.preference.OnPreferenceDataStoreChangeListener
import com.github.shadowsocks.utils.Key
import com.github.shadowsocks.utils.SingleInstanceActivity
import com.github.shadowsocks.widget.ListHolderListener
import com.github.shadowsocks.widget.ServiceButton
import com.github.shadowsocks.widget.StatsBar
import com.google.android.material.navigation.NavigationView
import com.google.android.material.snackbar.Snackbar
import com.google.gson.Gson
import com.google.gson.JsonArray
import com.google.gson.JsonObject
import com.sama.app.Api
import com.sama.app.ClipboardHelper
import com.sama.app.NativeMethod
import retrofit2.Call
import retrofit2.Callback
import retrofit2.Response
import java.lang.ref.WeakReference
import java.text.DateFormat
import java.text.SimpleDateFormat

class MainActivity : AppCompatActivity(), ShadowsocksConnection.Callback,
    OnPreferenceDataStoreChangeListener,
    NavigationView.OnNavigationItemSelectedListener {
    companion object {
        private const val TAG = "ShadowsocksMainActivity"
        private const val REQUEST_CONNECT = 1

        var stateListener: ((BaseService.State) -> Unit)? = null
    }

    // UI
    private lateinit var fab: ServiceButton
    private lateinit var stats: StatsBar
    internal lateinit var drawer: DrawerLayout
    private lateinit var navigation: NavigationView

    private lateinit var mTvPriKey: TextView
    private lateinit var mTvAddress: TextView
    private lateinit var mLlTip: LinearLayout
    private lateinit var mLlNodesContent: LinearLayout
    private lateinit var mIvCloseTip: ImageView
    private lateinit var mFlStart: FrameLayout
    private lateinit var mIvSelectCountry: ImageView
    private lateinit var mTvSelectNodes: TextView
    private lateinit var mSvNotesContent: ScrollView
    private lateinit var mLlMainContent: LinearLayout
    private lateinit var mLlSelectNodes: LinearLayout
    private lateinit var mIvUpDown: ImageView
    private lateinit var mLlNodesContentTop: LinearLayout
    private lateinit var mVLine: View
    private var mIsShowNodes = false
    private lateinit var mSelectView: View
    private lateinit var mIvShowPrivateKey: ImageView
    private lateinit var mClipboardHelper: ClipboardHelper
    private lateinit var mIvOpen: ImageView
    private lateinit var mIvCopyPriKey: ImageView
    private lateinit var mIvCopyAddress: ImageView
    private lateinit var mTvCrePriKey: TextView
    private lateinit var mTvImportPriKey: TextView
    private lateinit var mTvExpirationTime: TextView
    private lateinit var mIvRefresh: ImageView
    private var audiorIP: String = ""
    private var workerIp: String = ""
    lateinit var snackbar: CoordinatorLayout private set
    fun snackbar(text: CharSequence = "") =


        Snackbar.make(snackbar, text, Snackbar.LENGTH_LONG).apply {
            anchorView = fab
        }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // 开启
        NativeMethod.startSamah(55520)
        Thread {
            mHandler.sendMessageDelayed(Message.obtain().apply {
                what = 1
                obj = ""
            }, 500)
        }.start()
        SingleInstanceActivity.register(this) ?: return
        setContentView(R.layout.layout_main)
        mTvExpirationTime = findViewById(R.id.tv_expiration_time)
        mIvRefresh = findViewById(R.id.iv_refresh)
        mIvRefresh.setOnClickListener {
            if (this.state == BaseService.State.Connected) {
                Toast.makeText(
                    this@MainActivity,
                    "service Connected, can not do it",
                    Toast.LENGTH_SHORT
                ).show()
            } else {
                getNodeInfo(DataStore.address)
            }
        }
        mTvCrePriKey = findViewById(R.id.tv_cre_pri_key)
        mTvCrePriKey.setOnClickListener {
            if (this.state == BaseService.State.Connected) {
                Toast.makeText(
                    this@MainActivity,
                    "service Connected, can not do it",
                    Toast.LENGTH_SHORT
                ).show()
            } else {
                val builder = AlertDialog.Builder(this@MainActivity)
                builder.setTitle("Confirm")
                    .setMessage("Are you sure to overwrite the existing private key?")
                builder.setPositiveButton(
                    "confirm"
                ) { dialog, which ->
                    // 在此处添加确认按钮点击后的逻辑代码
                    createKeyOnly();
                }
                val dialog = builder.create()
                dialog.show()
            }
        }
        mTvImportPriKey = findViewById(R.id.tv_import_pri_key)
        mTvImportPriKey.setOnClickListener {
            if (this.state == BaseService.State.Connected) {
                Toast.makeText(
                    this@MainActivity,
                    "service Connected, can not do it",
                    Toast.LENGTH_SHORT
                ).show()
            } else {
                var et = EditText(this);
                val builder = AlertDialog.Builder(this@MainActivity)
                builder.setTitle("please input private key")
                builder.setView(et)
                builder.setCancelable(false)
                builder.setPositiveButton(
                    "confirm"
                ) { dialog, which ->
                    // 在此处添加确认按钮点击后的逻辑代码
                    var priKey = et.getText().toString();
                    if (priKey == "") {
                        Toast.makeText(
                            this@MainActivity,
                            "private key can not empty",
                            Toast.LENGTH_SHORT
                        ).show()
                    } else {
                        importPriKeyOnly(priKey)
                    }
                }
                builder.setNegativeButton("cancel") { dialog, which ->
                }
                val dialog = builder.create()
                dialog.show()
            }
        }
        mVLine = findViewById(R.id.v_nodes_line)
        mLlNodesContentTop = findViewById(R.id.ll_nodes_content_top)
        mSvNotesContent = findViewById(R.id.sv_notes_content)
        mLlMainContent = findViewById(R.id.ll_man_content)
        mIvUpDown = findViewById(R.id.iv_up_down)
        mLlNodesContent = findViewById(R.id.ll_nodes_content)
        mTvSelectNodes = findViewById(R.id.tv_select_nodes)
        mIvSelectCountry = findViewById(R.id.iv_select_country)
        mLlSelectNodes = findViewById(R.id.ll_select_nodes)
        mLlSelectNodes.setOnClickListener {
            if (this.state == BaseService.State.Connected) {
                Toast.makeText(
                    this@MainActivity,
                    "service Connected, can not do it",
                    Toast.LENGTH_SHORT
                ).show()
            } else {
                if (!mIsShowNodes) {
                    mIsShowNodes = true
                    mIvUpDown.setImageResource(R.mipmap.up)
                    mLlMainContent.visibility = View.GONE
                    mSvNotesContent.visibility = View.VISIBLE
                    mLlSelectNodes.setBackgroundColor(Color.TRANSPARENT)
                    mLlNodesContentTop.setBackgroundResource(R.drawable.notes_bg)
                    mVLine.visibility = View.VISIBLE
                } else {
                    hideNodes()
                }
            }
        }
        mIvCopyAddress = findViewById(R.id.iv_copy_address)
        mIvCopyAddress.setOnClickListener {
            mClipboardHelper.copyText(DataStore.address);
            Toast.makeText(this@MainActivity, "copy address success", Toast.LENGTH_SHORT).show()
        }
        mIvCopyPriKey = findViewById(R.id.iv_copy_private_key)
        mIvCopyPriKey.setOnClickListener {
            mClipboardHelper.copyText(DataStore.privateKey);
            Toast.makeText(this@MainActivity, "copy private key success", Toast.LENGTH_SHORT).show()
        }
        mClipboardHelper = ClipboardHelper(this)
        mIvShowPrivateKey = findViewById(R.id.iv_show_private_key)
        Log.e(TAG, "isHidePrivateKey: " + DataStore.isHidePrivateKey);
        mIvShowPrivateKey.setOnClickListener {
            if (DataStore.isHidePrivateKey) {
                mTvPriKey.text = DataStore.privateKey
                DataStore.isHidePrivateKey = false
                Log.e(TAG, "isHidePrivateKey: " + DataStore.isHidePrivateKey);
                mIvShowPrivateKey.setImageResource(R.mipmap.hide)
            } else {
                mTvPriKey.text = "************************************************************"
                DataStore.isHidePrivateKey = true
                mIvShowPrivateKey.setImageResource(R.mipmap.show)
                Log.e(TAG, "isHidePrivateKey: " + DataStore.isHidePrivateKey);
            }
        }
        mTvPriKey = findViewById(R.id.tv_pri_key)
        mTvAddress = findViewById(R.id.tv_address)
        // 判断本地是否存在
        if ("" != DataStore.address) {
            if (DataStore.isHidePrivateKey) {
                mTvPriKey.text = "************************************************************"
                mIvShowPrivateKey.setImageResource(R.mipmap.show)
            } else {
                mTvPriKey.text = DataStore.privateKey
                mIvShowPrivateKey.setImageResource(R.mipmap.hide)
            }
            mTvAddress.text = DataStore.address
        }
        mLlTip = findViewById(R.id.ll_tip)
        mIvCloseTip = findViewById(R.id.iv_close_tip)
        mIvCloseTip.setOnClickListener { mLlTip.visibility = View.GONE }
        mFlStart = findViewById(R.id.fl_start)
        mIvOpen = findViewById(R.id.iv_open)
        snackbar = findViewById(R.id.snackbar)
        snackbar.setOnApplyWindowInsetsListener(ListHolderListener)
        stats = findViewById(R.id.stats)
        stats.setOnClickListener { if (state == BaseService.State.Connected) stats.testConnection() }
        drawer = findViewById(R.id.drawer)
        drawer.systemUiVisibility =
            View.SYSTEM_UI_FLAG_LAYOUT_STABLE or View.SYSTEM_UI_FLAG_LAYOUT_HIDE_NAVIGATION
        drawer.setDrawerLockMode(DrawerLayout.LOCK_MODE_LOCKED_CLOSED)
        navigation = findViewById(R.id.navigation)
        navigation.setNavigationItemSelectedListener(this)
        if (savedInstanceState == null) {
            navigation.menu.findItem(R.id.profiles).isChecked = true
            displayFragment(ProfilesFragment())
        }

        fab = findViewById(R.id.fab)
        fab.setOnClickListener { toggle() }
        mFlStart.setOnClickListener {
            if (!DataStore.isVip){
                Toast.makeText(
                    this@MainActivity,
                    "is not vip",
                    Toast.LENGTH_SHORT
                )
                    .show()
            }else{
                if (workerIp != "") {
                    toggle()
                } else {
                    Toast.makeText(
                        this@MainActivity,
                        "loading nodes please wait...",
                        Toast.LENGTH_SHORT
                    )
                        .show()
                }
            }
        }
        fab.setOnApplyWindowInsetsListener { view, insets ->
            view.updateLayoutParams<ViewGroup.MarginLayoutParams> {
                bottomMargin = insets.systemWindowInsetBottom +
                        resources.getDimensionPixelOffset(R.dimen.mtrl_bottomappbar_fab_bottom_margin)
            }
            insets
        }

        changeState(BaseService.State.Idle) // reset everything to init state
        connection.connect(this, this)
        DataStore.publicStore.registerChangeListener(this)
    }

    private val customTabsIntent by lazy {
        CustomTabsIntent.Builder().apply {
            setColorScheme(CustomTabsIntent.COLOR_SCHEME_SYSTEM)
            setColorSchemeParams(
                CustomTabsIntent.COLOR_SCHEME_LIGHT,
                CustomTabColorSchemeParams.Builder().apply {
                    setToolbarColor(
                        ContextCompat.getColor(
                            this@MainActivity,
                            R.color.light_color_primary
                        )
                    )
                }.build()
            )
            setColorSchemeParams(
                CustomTabsIntent.COLOR_SCHEME_DARK,
                CustomTabColorSchemeParams.Builder().apply {
                    setToolbarColor(
                        ContextCompat.getColor(
                            this@MainActivity,
                            R.color.dark_color_primary
                        )
                    )
                }.build()
            )
        }.build()
    }

    fun launchUrl(uri: String) = try {
        customTabsIntent.launchUrl(this, uri.toUri())
    } catch (_: ActivityNotFoundException) {
        snackbar(uri).show()
    }

    // service
    var state = BaseService.State.Idle
    override fun stateChanged(state: BaseService.State, profileName: String?, msg: String?) =
        changeState(state, msg, true)

    override fun trafficUpdated(profileId: Long, stats: TrafficStats) {
        if (profileId == 0L) this@MainActivity.stats.updateTraffic(
            stats.txRate, stats.rxRate, stats.txTotal, stats.rxTotal
        )
        if (state != BaseService.State.Stopping) {
            (supportFragmentManager.findFragmentById(R.id.fragment_holder) as? ProfilesFragment)
                ?.onTrafficUpdated(profileId, stats)
        }
    }

    override fun trafficPersisted(profileId: Long) {
        ProfilesFragment.instance?.onTrafficPersisted(profileId)
    }

    /**
     * 监听连接状态
     */
    private fun changeState(
        state: BaseService.State,
        msg: String? = null,
        animate: Boolean = false
    ) {
        Log.e(TAG, "state: " + state)
        fab.changeState(state, this.state, animate)
        stats.changeState(state)
        if (msg != null) snackbar(getString(R.string.vpn_error, msg)).show()
        this.state = state
        ProfilesFragment.instance?.profilesAdapter?.notifyDataSetChanged()  // refresh button enabled state
        stateListener?.invoke(state)
        if (this.state == BaseService.State.Stopped) {
            stop()
        }
    }

    private fun toggle() = when {
        state.canStop -> {
            stop()

            Log.e(TAG, "stopService")
        }

        DataStore.serviceMode == Key.modeVpn -> {
            val intent = VpnService.prepare(this)
            if (intent != null) startActivityForResult(intent, REQUEST_CONNECT)
            else onActivityResult(REQUEST_CONNECT, Activity.RESULT_OK, null)
        }

        else -> {
            Log.e(TAG, "startService")
            start(DataStore.address)
        }
    }

    private val handler = Handler()
    private val connection = ShadowsocksConnection(handler, true)
    override fun onServiceConnected(service: IShadowsocksService) = changeState(
        try {
            BaseService.State.values()[service.state]
        } catch (_: RemoteException) {
            BaseService.State.Idle
        }
    )

    override fun onServiceDisconnected() = changeState(BaseService.State.Idle)
    override fun onBinderDied() {
        connection.disconnect(this)
        connection.connect(this, this)
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        when {
            requestCode != REQUEST_CONNECT -> super.onActivityResult(requestCode, resultCode, data)
            resultCode == Activity.RESULT_OK -> {
                start(DataStore.address)
            }

            else -> {
                snackbar().setText(R.string.vpn_permission_denied).show()
                Crashlytics.log(
                    Log.ERROR,
                    TAG,
                    "Failed to start VpnService from onActivityResult: $data"
                )
            }
        }
    }

    private val mHandler = MyHandler(WeakReference(this))

    private class MyHandler(val wrActivity: WeakReference<MainActivity>) :
        Handler(Looper.getMainLooper()) {
        override fun handleMessage(msg: Message) {
            super.handleMessage(msg)
            wrActivity.get()?.run {
                when (msg.what) {
                    1 -> version();
                }
            }
        }
    }


    override fun onPreferenceDataStoreChanged(store: PreferenceDataStore, key: String) {
        when (key) {
            Key.serviceMode -> handler.post {
                connection.disconnect(this)
                connection.connect(this, this)
            }
        }
    }

    private fun displayFragment(fragment: ToolbarFragment) {
        supportFragmentManager.beginTransaction().replace(R.id.fragment_holder, fragment)
            .commitAllowingStateLoss()
        drawer.closeDrawers()
    }

    override fun onNavigationItemSelected(item: MenuItem): Boolean {
        if (item.isChecked) drawer.closeDrawers() else {
            when (item.itemId) {
                R.id.profiles -> {
                    displayFragment(ProfilesFragment())
                    connection.bandwidthTimeout =
                        connection.bandwidthTimeout   // request stats update
                }

                R.id.globalSettings -> displayFragment(GlobalSettingsFragment())
                R.id.about -> {
                    Core.analytics.logEvent("about", Bundle())
                    displayFragment(AboutFragment())
                }

                R.id.faq -> {
                    launchUrl(getString(R.string.faq_url))
                    return true
                }

                R.id.customRules -> displayFragment(CustomRulesFragment())
                else -> return false
            }
            item.isChecked = true
        }
        return true
    }

    override fun onStart() {
        super.onStart()
        connection.bandwidthTimeout = 500
    }

    override fun onBackPressed() {
        if (drawer.isDrawerOpen(GravityCompat.START)) drawer.closeDrawers() else {
            val currentFragment =
                supportFragmentManager.findFragmentById(R.id.fragment_holder) as ToolbarFragment
            if (!currentFragment.onBackPressed()) {
                if (currentFragment is ProfilesFragment) super.onBackPressed() else {
                    navigation.menu.findItem(R.id.profiles).isChecked = true
                    displayFragment(ProfilesFragment())
                }
            }
        }
    }

    override fun onKeyShortcut(keyCode: Int, event: KeyEvent) = when {
        keyCode == KeyEvent.KEYCODE_G && event.hasModifiers(KeyEvent.META_CTRL_ON) -> {
            toggle()
            true
        }

        keyCode == KeyEvent.KEYCODE_T && event.hasModifiers(KeyEvent.META_CTRL_ON) -> {
            stats.testConnection()
            true
        }

        else -> (supportFragmentManager.findFragmentById(R.id.fragment_holder) as ToolbarFragment).toolbar.menu.let {
            it.setQwertyMode(KeyCharacterMap.load(event.deviceId).keyboardType != KeyCharacterMap.NUMERIC)
            it.performShortcut(keyCode, event, 0)
        }
    }

    override fun onStop() {
        connection.bandwidthTimeout = 0
        super.onStop()
    }

    override fun onDestroy() {
        super.onDestroy()
        // 开启
        NativeMethod.stopSamah()
        DataStore.publicStore.unregisterChangeListener(this)
        connection.disconnect(this)
        BackupManager(this).dataChanged()
        handler.removeCallbacksAndMessages(null)
    }

    private fun version() {
        val params = HashMap<String, String>()
        val body = HashMap<String, Any>()
        body["method"] = "sama.version"
        body["params"] = params
        Api.getInstance().apiService.call(body).enqueue(object : Callback<JsonObject?> {
            override fun onResponse(call: Call<JsonObject?>, response: Response<JsonObject?>) {
                if (!response.isSuccessful) {
                    onFailure(call, RuntimeException(response.message()))
                    return
                }
                val body = response.body()
                Log.e(TAG, "version onResponse: " + body.toString())
                samaTest()
            }

            override fun onFailure(call: Call<JsonObject?>, t: Throwable) {
                Log.e(TAG, "version onFailure: " + t.message)
                Toast.makeText(this@MainActivity, "sama.version failure", Toast.LENGTH_SHORT).show()
            }
        })
    }

    private fun workPort(address: String) {
        val params = java.util.HashMap<String, Any>()
        params["address"] = address
        val body = java.util.HashMap<String, Any>()
        body["method"] = "sama.workPort"
        body["params"] = params
        Api.getInstance().apiService.call(body).enqueue(object : Callback<JsonObject?> {
            override fun onResponse(call: Call<JsonObject?>, response: Response<JsonObject?>) {
                if (!response.isSuccessful) {
                    onFailure(call, java.lang.RuntimeException(response.message()))
                    return
                }
                val body = response.body()
                Log.e(TAG, "workPort onResponse: " + body.toString())
                val result = body!!.getAsJsonObject("result")
                if (null == result) {
                    Toast.makeText(
                        this@MainActivity,
                        "sama.workPort error：" + body.toString(),
                        Toast.LENGTH_SHORT
                    )
                        .show()
                    return
                }
                var socks5 = result["socks5"].asInt;
                DataStore.portProxy = socks5
                //setVipInfo(address)
                getVipInfo(address)
                getNodeInfo(address)
            }

            override fun onFailure(call: Call<JsonObject?>, t: Throwable) {
                Log.e(TAG, "sama.workPort failure: " + t.message)
            }
        })
    }

    private fun samaTest() {
        val paramsMap = java.util.HashMap<String, Int>()
        paramsMap["id"] = 4
        val body = java.util.HashMap<String, Any>()
        body["method"] = "sama.test"
        body["params"] = paramsMap
        Api.getInstance().apiService.call(body).enqueue(object : Callback<JsonObject?> {
            override fun onResponse(call: Call<JsonObject?>, response: Response<JsonObject?>) {
                if (!response.isSuccessful) {
                    onFailure(call, java.lang.RuntimeException(response.message()))
                    return
                }
                val body = response.body()
                Log.e(TAG, "samaTest onResponse: " + body.toString())
                val result = body!!.getAsJsonObject("result")
                if (null == result) {
                    Toast.makeText(
                        this@MainActivity,
                        "sama.test error：" + body.toString(),
                        Toast.LENGTH_SHORT
                    )
                        .show()
                    return
                }
                var bSucc = result["bSucc"].asBoolean;
                if (!bSucc) {
                    Toast.makeText(
                        this@MainActivity,
                        "sama.test false：" + body.toString(),
                        Toast.LENGTH_SHORT
                    )
                        .show()
                    return
                }
                // 判断本地是否存在
                if ("" == DataStore.address) {
                    createKey()
                    return
                }
                importPriKey(DataStore.privateKey, DataStore.address)
            }

            override fun onFailure(call: Call<JsonObject?>, t: Throwable) {
                Log.e(TAG, "samaTest onFailure: " + t.message)
                Toast.makeText(
                    this@MainActivity,
                    "sama.test failure：" + body.toString(),
                    Toast.LENGTH_SHORT
                )
                    .show()
            }
        })
    }

    private fun createKeyOnly() {
        val body = java.util.HashMap<String, Any>()
        body["method"] = "sama.createKey"
        body["params"] = Any()
        Api.getInstance().apiService.call(body).enqueue(object : Callback<JsonObject?> {
            override fun onResponse(call: Call<JsonObject?>, response: Response<JsonObject?>) {
                if (!response.isSuccessful) {
                    onFailure(call, java.lang.RuntimeException(response.message()))
                    return
                }
                val body = response.body()
                Log.e(TAG, "createKey onResponse: " + body.toString())
                val result = body!!.getAsJsonObject("result")
                if (null == result) {
                    Toast.makeText(
                        this@MainActivity,
                        "sama.createKey error：" + body.toString(),
                        Toast.LENGTH_SHORT
                    )
                        .show()
                    return
                }
                val address = result["address"].asString
                val priKey = result["priKey"].asString
                DataStore.privateKey = priKey
                DataStore.address = address
                if (DataStore.isHidePrivateKey) {
                    mTvPriKey.text = "************************************************************"
                    mIvShowPrivateKey.setImageResource(R.mipmap.show)
                } else {
                    mTvPriKey.text = DataStore.privateKey
                    mIvShowPrivateKey.setImageResource(R.mipmap.hide)
                }
                mTvAddress.text = address
                Toast.makeText(
                    this@MainActivity,
                    "createKey success",
                    Toast.LENGTH_SHORT
                )
                    .show()
            }

            override fun onFailure(call: Call<JsonObject?>, t: Throwable) {
                Log.e(TAG, "createKey onFailure: " + t.message)
                Toast.makeText(
                    this@MainActivity,
                    "sama.createKey failure：" + t.message,
                    Toast.LENGTH_SHORT
                )
                    .show()
            }
        })
    }

    private fun createKey() {
        val body = java.util.HashMap<String, Any>()
        body["method"] = "sama.createKey"
        body["params"] = Any()
        Api.getInstance().apiService.call(body).enqueue(object : Callback<JsonObject?> {
            override fun onResponse(call: Call<JsonObject?>, response: Response<JsonObject?>) {
                if (!response.isSuccessful) {
                    onFailure(call, java.lang.RuntimeException(response.message()))
                    return
                }
                val body = response.body()
                Log.e(TAG, "createKey onResponse: " + body.toString())
                val result = body!!.getAsJsonObject("result")
                if (null == result) {
                    Toast.makeText(
                        this@MainActivity,
                        "sama.createKey error：" + body.toString(),
                        Toast.LENGTH_SHORT
                    )
                        .show()
                    return
                }
                val address = result["address"].asString
                val priKey = result["priKey"].asString
                DataStore.privateKey = priKey
                DataStore.address = address
                if (DataStore.isHidePrivateKey) {
                    mTvPriKey.text = "************************************************************"
                    mIvShowPrivateKey.setImageResource(R.mipmap.show)
                } else {
                    mTvPriKey.text = DataStore.privateKey
                    mIvShowPrivateKey.setImageResource(R.mipmap.hide)
                }
                mTvAddress.text = address

                importPriKey(priKey, address)
            }

            override fun onFailure(call: Call<JsonObject?>, t: Throwable) {
                Log.e(TAG, "createKey onFailure: " + t.message)
                Toast.makeText(
                    this@MainActivity,
                    "sama.createKey failure：" + t.message,
                    Toast.LENGTH_SHORT
                )
                    .show()
            }
        })
    }

    private fun importPriKeyOnly(priKey: String) {
        val priKeyMap = java.util.HashMap<String, String>()
        priKeyMap["priKey"] = priKey
        val body = java.util.HashMap<String, Any>()
        body["method"] = "sama.importKey"
        body["params"] = priKeyMap
        Api.getInstance().apiService.call(body).enqueue(object : Callback<JsonObject?> {
            override fun onResponse(call: Call<JsonObject?>, response: Response<JsonObject?>) {
                if (!response.isSuccessful) {
                    onFailure(call, java.lang.RuntimeException(response.message()))
                    return
                }
                val body = response.body()
                Log.e(TAG, "importPriKey onResponse: " + body.toString())
                val result = body!!.getAsJsonObject("result")
                if (null == result) {
                    Toast.makeText(
                        this@MainActivity,
                        "sama.importKey error：" + body.toString(),
                        Toast.LENGTH_SHORT
                    )
                        .show()
                    return
                }
                var bSucc = result["bSucc"].asBoolean;
                if (!bSucc) {
                    Toast.makeText(
                        this@MainActivity,
                        "sama.importKey false：" + body.toString(),
                        Toast.LENGTH_SHORT
                    )
                        .show()
                    return
                }
                val address = result["address"].asString
                val privateKey = result["priKey"].asString
                DataStore.privateKey = privateKey
                DataStore.address = address
                if (DataStore.isHidePrivateKey) {
                    mTvPriKey.text = "************************************************************"
                    mIvShowPrivateKey.setImageResource(R.mipmap.show)
                } else {
                    mTvPriKey.text = DataStore.privateKey
                    mIvShowPrivateKey.setImageResource(R.mipmap.hide)
                }
                mTvAddress.text = address
                Toast.makeText(
                    this@MainActivity,
                    "importKey success",
                    Toast.LENGTH_SHORT
                )
                    .show()
            }

            override fun onFailure(call: Call<JsonObject?>, t: Throwable) {
                Log.e(TAG, "importPriKey onFailure: " + t.message)
                Toast.makeText(
                    this@MainActivity,
                    "sama.importPriKey failure：" + t.message,
                    Toast.LENGTH_SHORT
                )
                    .show()
            }
        })
    }

    private fun importPriKey(priKey: String, address: String) {
        val priKeyMap = java.util.HashMap<String, String>()
        priKeyMap["priKey"] = priKey
        val body = java.util.HashMap<String, Any>()
        body["method"] = "sama.importKey"
        body["params"] = priKeyMap
        Api.getInstance().apiService.call(body).enqueue(object : Callback<JsonObject?> {
            override fun onResponse(call: Call<JsonObject?>, response: Response<JsonObject?>) {
                if (!response.isSuccessful) {
                    onFailure(call, java.lang.RuntimeException(response.message()))
                    return
                }
                val body = response.body()
                Log.e(TAG, "importPriKey onResponse: " + body.toString())
                val result = body!!.getAsJsonObject("result")
                if (null == result) {
                    Toast.makeText(
                        this@MainActivity,
                        "sama.importKey error：" + body.toString(),
                        Toast.LENGTH_SHORT
                    )
                        .show()
                    return
                }
                var bSucc = result["bSucc"].asBoolean;
                if (!bSucc) {
                    Toast.makeText(
                        this@MainActivity,
                        "sama.importKey false：" + body.toString(),
                        Toast.LENGTH_SHORT
                    )
                        .show()
                    return
                }
                workPort(address)
            }

            override fun onFailure(call: Call<JsonObject?>, t: Throwable) {
                Log.e(TAG, "importPriKey onFailure: " + t.message)
                Toast.makeText(
                    this@MainActivity,
                    "sama.importPriKey failure：" + t.message,
                    Toast.LENGTH_SHORT
                )
                    .show()
            }
        })
    }

    private fun setVipInfo(address: String) {
        val params = java.util.HashMap<String, Any>()
        params["address"] = address
        params["vip"] = true
        params["startTime"] = 1587940040
        params["endTime"] = 1705763886
        val body = java.util.HashMap<String, Any>()
        body["method"] = "sama.setVipInfo"
        body["params"] = params
        Api.getInstance().apiService.call(body).enqueue(object : Callback<JsonObject?> {
            override fun onResponse(call: Call<JsonObject?>, response: Response<JsonObject?>) {
                if (!response.isSuccessful) {
                    onFailure(call, java.lang.RuntimeException(response.message()))
                    return
                }
                val body = response.body()
                Log.e(TAG, "setVipInfo onResponse: " + body.toString())
                val result = body!!.getAsJsonObject("result")
                if (null == result) {
                    Toast.makeText(
                        this@MainActivity,
                        "sama.setVipInfo error：" + body.toString(),
                        Toast.LENGTH_SHORT
                    )
                        .show()
                    return
                }
                var bSucc = result["bSucc"].asBoolean;
                if (!bSucc) {
                    Toast.makeText(
                        this@MainActivity,
                        "sama.setVipInfo false：" + body.toString(),
                        Toast.LENGTH_SHORT
                    )
                        .show()
                    return
                }
                getVipInfo(address)
            }

            override fun onFailure(call: Call<JsonObject?>, t: Throwable) {
                Log.e(TAG, "setVipInfo onFailure: " + t.message)
                Toast.makeText(
                    this@MainActivity,
                    "sama.setVipInfo failure：" + t.message,
                    Toast.LENGTH_SHORT
                )
                    .show()
            }
        })
    }

    private fun getVipInfo(address: String) {
        val params = java.util.HashMap<String, Any>()
        params["address"] = address
        val body = java.util.HashMap<String, Any>()
        body["method"] = "sama.getVipInfo"
        body["params"] = params
        Api.getInstance().apiService.call(body).enqueue(object : Callback<JsonObject?> {
            override fun onResponse(call: Call<JsonObject?>, response: Response<JsonObject?>) {
                if (!response.isSuccessful) {
                    onFailure(call, java.lang.RuntimeException(response.message()))
                    return
                }
                val body = response.body()
                Log.e(TAG, "getVipInfo onResponse: " + body.toString())
                val result = body!!.getAsJsonObject("result")
                if (null == result) {
                    Toast.makeText(
                        this@MainActivity,
                        "sama.getVipInfo error：" + body.toString(),
                        Toast.LENGTH_SHORT
                    )
                        .show()
                    mTvExpirationTime.text = "Expiration Time:Expired"
                    DataStore.isVip = false
                    return
                }
                var vip = result["vip"].asBoolean
                DataStore.isVip = vip
                var endTime = result["endTime"].asString
                val endTimeLong = java.lang.Long.valueOf(endTime + "000")
                val dateFormat: DateFormat = SimpleDateFormat("yyyy-MM-dd")
                val format = dateFormat.format(endTimeLong)
                mTvExpirationTime.text = "Expiration Time:" + format
            }

            override fun onFailure(call: Call<JsonObject?>, t: Throwable) {
                Log.e(TAG, "getVipInfo onFailure: " + t.message)
                Toast.makeText(
                    this@MainActivity,
                    "sama.getVipInfo failure：" + t.message,
                    Toast.LENGTH_SHORT
                )
                    .show()
            }
        })
    }


    private fun getNodeInfo(address: String) {
        val params = java.util.HashMap<String, String>()
        params["address"] = address
        val body = java.util.HashMap<String, Any>()
        body["method"] = "sama.getNodeInfo"
        body["params"] = params
        Api.getInstance().apiService.call(body).enqueue(object : Callback<JsonObject?> {
            override fun onResponse(call: Call<JsonObject?>, response: Response<JsonObject?>) {
                if (!response.isSuccessful) {
                    onFailure(call, java.lang.RuntimeException(response.message()))
                    return
                }
                val body = response.body()
                Log.e(TAG, "getNodeInfo onResponse: " + body.toString())
                val result = body!!.getAsJsonObject("result")
                if (null == result) {
                    Toast.makeText(
                        this@MainActivity,
                        "sama.getNodeInfo error：" + body.toString(),
                        Toast.LENGTH_SHORT
                    )
                        .show()
                    return
                }
                val nodes = result.getAsJsonArray("nodes")
                var isCheckDefault = false
                mLlNodesContent.removeAllViews()
                val aa = java.util.HashMap<String, String>()
                // 使用Map来存储每个字符串的出现次数和第一次出现的位置
                val map: MutableMap<String, MutableList<Int>?> = java.util.HashMap()
                for (i in 0 until nodes.size()) {
                    val country: String =
                        nodes.get(i).asJsonObject["country"].asString
                    val stakerType = nodes.get(i).asJsonObject["stakerType"].asInt
                    if (stakerType == 7) {
                        if (!map.containsKey(country)) {
                            map[country] = ArrayList()
                        }
                        map[country]!!.add(i)
                    }
                }
                // 遍历每个字符串，根据出现次数和第一次出现的位置进行重命名
                for (i in 0 until nodes.size()) {
                    val country: String =
                        nodes.get(i).asJsonObject["country"].asString
                    val publicIP: String =
                        nodes.get(i).asJsonObject["publicIP"].asString
                    val stakerType = nodes.get(i).asJsonObject["stakerType"].asInt
                    if (stakerType == 7) {
                        val positions: List<Int>? = map[country]
                        // 计算当前位置应该使用哪个名称
                        var count = 1
                        val firstIndex = positions!![0]
                        if (i != firstIndex) {
                            count++
                        }
                        for (j in 1 until positions.size) {
                            val nextIndex = positions[j]
                            if (nextIndex > i) {
                                break
                            } else if (nextIndex != i) {
                                count++
                            }
                        }
                        val newName = country + " - Node " + count
                        println(newName)
                        aa[publicIP] = newName
                    }
                }

                for (node in nodes) {
                    val country = node.asJsonObject["country"].asString
                    val publicIP = node.asJsonObject["publicIP"].asString
                    val stakerType = node.asJsonObject["stakerType"].asInt
                    if (stakerType == 7) {
                        val inflate =
                            layoutInflater.inflate(R.layout.layout_nodes_list, null, false)
                        val viewById = inflate.findViewById<TextView>(R.id.tv_nodes_name)
                        viewById.setText(aa.get(publicIP))
                        if (!isCheckDefault) {
                            isCheckDefault = true
                            mTvSelectNodes.setText(aa.get(publicIP))
                            mIvSelectCountry.setImageResource(R.mipmap.node_image_1)
                            mSelectView = inflate
                            inflate.findViewById<View>(R.id.iv_checked).visibility =
                                View.VISIBLE
                            workerIp = publicIP
                            audiorIP = getAaudiorIP(country, nodes)
                            Log.e(
                                TAG,
                                "country：" + country + ",workerIp:" + workerIp + "" + ",audiorIP:" + audiorIP
                            )
                        }
                        inflate.setOnClickListener { v ->
                            mSelectView.findViewById<View>(R.id.iv_checked).visibility =
                                View.GONE
                            mSelectView = v
                            v.findViewById<View>(R.id.iv_checked).visibility =
                                View.VISIBLE
                            mTvSelectNodes.text = aa.get(publicIP)
                            mIvSelectCountry.setImageResource(R.mipmap.node_image_1)
                            workerIp = publicIP
                            audiorIP = getAaudiorIP(country, nodes)
                            Log.e(
                                TAG,
                                "country：" + country + ",workerIp:" + workerIp + "" + ",audiorIP:" + audiorIP
                            )
                            hideNodes()
                        }
                        mLlNodesContent.addView(inflate)
                    }
                }
                Toast.makeText(
                    this@MainActivity,
                    "refresh success",
                    Toast.LENGTH_SHORT
                )
                    .show()
                //start(address)
            }

            override fun onFailure(call: Call<JsonObject?>, t: Throwable) {
                Log.e(TAG, "getNodeInfo onFailure: " + t.message)
                Toast.makeText(
                    this@MainActivity,
                    "getNodeInfo onFailure: " + t.message,
                    Toast.LENGTH_SHORT
                )
                    .show()
            }
        })
    }

    fun getAaudiorIP(country: String?, nodes: JsonArray): String {
        var defaultAaudiorIp: String? = ""
        val workIp = java.util.HashMap<String, String?>()
        for (node in nodes) {
            val country1 = node.asJsonObject["country"].asString
            val stakerType = node.asJsonObject["stakerType"].asInt
            val publicIP = node.asJsonObject["publicIP"].asString
            if (stakerType == 6) {
                workIp[country1] = publicIP
                defaultAaudiorIp = publicIP
            }
        }
        val a = """
                {
                "AR":["AR","BR","CA","US","PT","ES","AT","FR","GB","IT","BE","GR","NL","DK","HU","TR","DE","IL","NO","SE","FI","IN","AU","ID","MY","SG","HK","PH","TW","KR","JP","NZ"],
                "AT":["AT","FR","BE","NL","GB","DK","IT","ES","DE","HU","NO","PT","GR","SE","TR","FI","IL","IN","CA","BR","US","AR","ID","AU","MY","SG","HK","TW","PH","KR","JP","NZ"],
                "AU":["AU","ID","SG","MY","IN","PH","HK","TW","KR","NZ","IL","JP","TR","GR","HU","IT","DE","SE","FI","AT","BE","FR","ES","NL","NO","DK","PT","GB","BR","AR","CA","US"],
                "BE":["BE","NL","FR","AT","GB","DK","DE","NO","IT","ES","HU","SE","PT","GR","TR","FI","IL","IN","CA","BR","US","ID","AR","AU","MY","SG","HK","TW","PH","KR","JP","NZ"],
                "BR":["BR","AR","PT","CA","ES","US","AT","FR","GB","IT","BE","GR","NL","DK","HU","TR","DE","IL","NO","SE","FI","IN","AU","ID","MY","SG","HK","PH","TW","KR","JP","NZ"],
                "CA":["CA","US","BR","PT","ES","GB","AR","FR","AT","BE","NL","DK","NO","IT","DE","HU","SE","GR","TR","FI","IL","IN","AU","ID","MY","SG","HK","TW","PH","KR","JP","NZ"],
                "DE":["DE","HU","DK","NO","SE","NL","BE","AT","IT","FR","GB","GR","FI","TR","ES","PT","IL","IN","CA","BR","ID","MY","AU","SG","HK","TW","US","AR","PH","KR","JP","NZ"],
                "DK":["DK","NL","BE","NO","DE","GB","FR","AT","SE","HU","IT","ES","FI","GR","PT","TR","IL","IN","CA","BR","ID","US","MY","AU","SG","AR","HK","TW","PH","KR","JP","NZ"],
                "ES":["ES","PT","AT","FR","GB","BE","NL","IT","DK","DE","HU","GR","NO","TR","SE","FI","IL","BR","CA","IN","AR","US","AU","ID","MY","SG","HK","TW","PH","KR","JP","NZ"],
                "FI":["FI","SE","NO","DE","HU","DK","NL","BE","IT","TR","AT","FR","GR","GB","IL","ES","PT","IN","ID","MY","HK","SG","CA","AU","TW","KR","BR","PH","JP","US","AR","NZ"],
                "FR":["FR","AT","BE","GB","NL","DK","ES","DE","IT","NO","HU","PT","SE","GR","TR","FI","IL","IN","CA","BR","US","AR","ID","AU","MY","SG","HK","TW","PH","KR","JP","NZ"],
                "GB":["GB","FR","BE","NL","AT","DK","ES","DE","NO","PT","IT","HU","SE","GR","TR","FI","IL","CA","IN","BR","US","AR","ID","AU","MY","SG","HK","TW","PH","KR","JP","NZ"],
                "GR":["GR","TR","IT","HU","IL","DE","AT","BE","FR","NL","SE","DK","ES","NO","GB","FI","PT","IN","BR","ID","AU","MY","SG","CA","HK","TW","PH","KR","AR","US","JP","NZ"],
                "HK":["HK","TW","PH","KR","MY","SG","JP","ID","IN","AU","NZ","IL","TR","GR","FI","HU","SE","IT","DE","NO","DK","AT","NL","BE","FR","GB","ES","PT","BR","AR","CA","US"],
                "HU":["HU","DE","IT","GR","TR","SE","AT","BE","NL","DK","NO","FR","GB","FI","ES","IL","PT","IN","BR","ID","CA","MY","AU","SG","HK","TW","PH","KR","AR","US","JP","NZ"],
                "ID":["ID","MY","SG","AU","PH","HK","IN","TW","KR","JP","NZ","IL","TR","GR","HU","IT","FI","DE","SE","AT","NO","BE","NL","FR","DK","ES","GB","PT","BR","AR","CA","US"],
                "IL":["IL","TR","GR","HU","IT","DE","SE","AT","BE","NL","FI","FR","NO","DK","ES","GB","IN","PT","ID","AU","MY","SG","HK","TW","PH","BR","KR","JP","CA","AR","US","NZ"],
                "IN":["IN","ID","MY","SG","AU","HK","IL","PH","TW","TR","GR","KR","HU","IT","FI","SE","DE","JP","NO","AT","BE","NL","DK","FR","ES","GB","PT","NZ","BR","AR","CA","US"],
                "IT":["IT","HU","GR","AT","DE","BE","FR","TR","NL","DK","GB","ES","NO","SE","PT","IL","FI","IN","BR","CA","ID","AU","MY","SG","HK","AR","TW","PH","US","KR","JP","NZ"],
                "JP":["JP","KR","TW","PH","HK","SG","MY","ID","IN","AU","NZ","IL","TR","FI","GR","HU","SE","IT","DE","NO","DK","NL","BE","AT","FR","GB","ES","PT","BR","AR","CA","US"],
                "KR":["KR","JP","TW","HK","PH","MY","SG","ID","IN","AU","NZ","IL","TR","FI","GR","HU","SE","IT","DE","NO","DK","NL","BE","AT","FR","GB","ES","PT","BR","AR","CA","US"],
                "MY":["MY","SG","ID","PH","HK","AU","TW","IN","KR","JP","NZ","IL","TR","GR","HU","IT","FI","SE","DE","NO","AT","BE","NL","DK","FR","ES","GB","PT","BR","AR","CA","US"],
                "NL":["NL","BE","DK","FR","AT","GB","DE","NO","IT","HU","SE","ES","PT","GR","FI","TR","IL","IN","CA","BR","US","ID","AU","MY","AR","SG","HK","TW","PH","KR","JP","NZ"],
                "NO":["NO","DK","SE","DE","NL","BE","FR","GB","HU","AT","FI","IT","GR","ES","TR","PT","IL","IN","CA","BR","ID","MY","AU","SG","HK","US","TW","AR","KR","PH","JP","NZ"],
                "NZ":["NZ","PH","SG","MY","ID","AU","TW","HK","JP","KR","IN","IL","TR","GR","HU","IT","FI","DE","SE","AT","NO","BE","NL","FR","DK","ES","GB","PT","BR","AR","CA","US"],
                "PH":["PH","TW","HK","SG","MY","KR","JP","ID","AU","IN","NZ","IL","TR","GR","HU","FI","IT","SE","DE","NO","AT","DK","NL","BE","FR","GB","ES","PT","BR","AR","CA","US"],
                "PT":["PT","ES","FR","GB","AT","BE","NL","IT","DK","DE","HU","GR","NO","TR","SE","IL","FI","BR","CA","IN","AR","US","AU","ID","MY","SG","HK","TW","PH","KR","JP","NZ"],
                "SE":["SE","NO","DE","FI","DK","HU","NL","BE","IT","AT","FR","GB","GR","TR","ES","IL","PT","IN","CA","ID","BR","MY","HK","SG","AU","TW","KR","PH","US","AR","JP","NZ"],
                "SG":["SG","MY","ID","PH","HK","AU","TW","IN","KR","JP","NZ","IL","TR","GR","HU","IT","FI","SE","DE","AT","NO","BE","NL","DK","FR","ES","GB","PT","BR","AR","CA","US"],
                "TR":["TR","GR","IL","HU","IT","DE","SE","AT","BE","NL","FR","DK","NO","FI","GB","ES","PT","IN","ID","AU","MY","SG","BR","HK","TW","PH","CA","KR","AR","JP","US","NZ"],
                "TW":["TW","HK","PH","KR","JP","MY","SG","ID","IN","AU","NZ","IL","TR","GR","FI","HU","SE","IT","DE","NO","DK","AT","NL","BE","FR","GB","ES","PT","BR","AR","CA","US"],
                "US":["US","CA","BR","AR","PT","ES","GB","FR","AT","BE","NL","DK","NO","IT","DE","HU","SE","GR","TR","FI","IL","IN","AU","ID","MY","SG","HK","TW","PH","KR","JP","NZ"]
                }
                """.trimIndent()
        val gson = Gson()
        val jsonObject = gson.fromJson(a, JsonObject::class.java)
        val asJsonArray = jsonObject.getAsJsonArray(country)
        for (jsonElement in asJsonArray) {
            val asString = jsonElement.asString
            if (workIp.containsKey(asString)) {
                Log.e(TAG, "Aaudior country : " + asString)
                return workIp[asString].toString()
            }
        }
        return defaultAaudiorIp.toString()
    }


    private fun hideNodes() {
        mIsShowNodes = false
        mIvUpDown.setImageResource(R.mipmap.down)
        mLlMainContent.visibility = View.VISIBLE
        mSvNotesContent.visibility = View.GONE
        mLlSelectNodes.setBackgroundColor(Color.parseColor("#282828"))
        mLlNodesContentTop.background = null
        mVLine.visibility = View.GONE
    }

    private fun start(address: String) {
        Log.e(TAG, "start audiorIP: " + audiorIP + ", workerIp:" + workerIp)
        val params = java.util.HashMap<String, Any>()
        params["address"] = address
        params["smartCN"] = false
        params["directServer"] = false
        params["AudiorIP"] = audiorIP
        params["WorkerIP"] = workerIp
        val body = java.util.HashMap<String, Any>()
        body["method"] = "sama.start"
        body["params"] = params
        Api.getInstance().apiService.call(body).enqueue(object : Callback<JsonObject?> {
            override fun onResponse(call: Call<JsonObject?>, response: Response<JsonObject?>) {
                if (!response.isSuccessful) {
                    onFailure(call, java.lang.RuntimeException(response.message()))
                    return
                }
                val body = response.body()
                Log.e(TAG, "start onResponse: " + body.toString())
                val result = body!!.getAsJsonObject("result")
                if (null == result) {
                    Toast.makeText(
                        this@MainActivity,
                        "sama.start error：" + body.toString(),
                        Toast.LENGTH_SHORT
                    )
                        .show()
                    return
                }
                val param = result["param"].asString
                DataStore.param = param
                Log.e(TAG, "onResponse: " + DataStore.param)
                Core.startService()
                mIvOpen.setImageResource(R.mipmap.right)
            }

            override fun onFailure(call: Call<JsonObject?>, t: Throwable) {
                Log.e(TAG, "start onFailure: " + t.message)
            }
        })
    }

    private fun stop() {
        val params = java.util.HashMap<String, Any>()
        val body = java.util.HashMap<String, Any>()
        body["method"] = "sama.stop"
        body["params"] = params
        Api.getInstance().apiService.call(body).enqueue(object : Callback<JsonObject?> {
            override fun onResponse(call: Call<JsonObject?>, response: Response<JsonObject?>) {
                if (!response.isSuccessful) {
                    onFailure(call, java.lang.RuntimeException(response.message()))
                    return
                }
                val body = response.body()
                Log.e(TAG, "stop onResponse: " + body.toString())
                val result = body!!.getAsJsonObject("result")
                if (null == result) {
                    Toast.makeText(
                        this@MainActivity,
                        "sama.stop error：" + body.toString(),
                        Toast.LENGTH_SHORT
                    )
                        .show()
                    return
                }
                var bSucc = result["bSucc"].asBoolean;
                if (!bSucc) {
                    Toast.makeText(
                        this@MainActivity,
                        "sama.stop false：" + body.toString(),
                        Toast.LENGTH_SHORT
                    )
                        .show()
                    return
                }
                Core.stopService()
                mIvOpen.setImageResource(R.mipmap.open)
            }

            override fun onFailure(call: Call<JsonObject?>, t: Throwable) {
                Log.e(TAG, "stop onFailure: " + t.message)
            }
        })
    }
}
