package oOoOoO0o0oOoOoO0;

import OoO0oO0o0oOo0O0O.C0014;
import OoOoO0o0Oo0Oo0o0.C0198;
import com.nmmedit.protect.NativeUtil;
import com.pop.d.base.xd.C0382;
import kotlinx.coroutines.flow.C0416;
import oOoO0O0oO0o0O0O0.C0487;
import oOoO0o0oOo0O0O0O.C0553;
import oOoOoO0O0oOo0oO0.oOoOoOo0oOo0o0oO;

/* loaded from: classes2.dex */
public class oOoOoOoOoOoOoO0o {

    /* renamed from: oOoOoOoOoOoOoO0o, reason: collision with root package name */
    /**
     * 解密后的字符串常量
     * 用途: 存储重要的配置信息或标识符
     * 通过双重解密从 f416short 数组中提取
     */
    public static final String f30498oOoOoOoOoOoOoO0o;

    /* renamed from: short, reason: not valid java name */
    /**
     * 加密数据数组
     * 包含: 474个short值，用于存储加密的字符串数据
     * 解密方式: 
     *   1. 通过 C0487.m1041() 从索引0开始解密 (key: C0382.f259 ^ 517, seed: 1574)
     *   2. 通过 C0198.m424() 从索引29开始解密 (key: C0014.f10 ^ (-133), seed: 1069)
     *   3. 两个解密结果拼接后，再通过 oOoOoOo0oOo0o0oO.oOoOoOoOoOoOoO0o() 进行最终解密
     * 
     * 作用: 隐藏重要的字符串信息，防止静态分析
     */
    private static final short[] f416short;

    /**
     * 静态初始化块
     * 
     * 执行时机: 类加载时自动执行
     * 
     * 功能分解:
     * 1. NativeUtil.classes2Init0(11)
     *    - 调用 libnmmp.so 的 JNI 方法
     *    - 注册第11个类的所有 Native 方法（即本类的15个native方法）
     *    - 这是动态注册JNI方法的关键步骤
     * 
     * 2. f416short = new short[]{...}
     *    - 初始化包含474个元素的加密数据数组
     *    - 这些数据是经过多层混淆的字符串
     *    - 数值范围: 640-3191，使用short类型节省空间
     * 
     * 3. f30498oOoOoOoOoOoOoO0o = ...
     *    - 三层解密流程:
     *      a) C0487.m1041(f416short, 0, C0382.f259 ^ 517, 1574)
     *         从数组索引0开始，使用XOR密钥解密第一部分
     *      b) C0198.m424(f416short, 29, C0014.f10 ^ (-133), 1069)
     *         从数组索引29开始，使用XOR密钥解密第二部分
     *      c) oOoOoOo0oOo0o0oO.oOoOoOoOoOoOoO0o(part1, part2)
     *         合并并最终解密得到明文字符串
     *    - 解密结果: 可能是配置信息、包名、类名或方法名等关键标识
     * 
     * 安全机制:
     * - 多层解密保护，难以静态分析
     * - XOR密钥动态计算
     * - 分段解密，增加破解难度
     */
    static {
        // 第1步: 注册本类的15个Native方法到libnmmp.so
        // 参数11表示这是第11个需要注册的类
        NativeUtil.classes2Init0(11);
        
        // 第2步: 初始化加密数据数组（474个short值）
        // 这些数据包含了加密的字符串信息
        f416short = new short[]{1615, 1662, 1600, 1654, 1556, 1636, 1645, 1623, 1655, 1545, 1556, 1633, 1602, 1566, 1662, 1663, 1645, 1623, 1622, 1605, 1619, 1645, 1610, 1558, 1617, 1554, 1651, 1652, 1580, 1051, 1093, 1092, 1092, 1044, 1088, 1121, 1131, 1120, 1044, 1120, 1040, 1063, 1785, 1738, 1784, 1733, 1781, 1783, 1758, 1791, 1752, 1771, 1697, 1697, 1686, 741, 728, 709, 657, 663, 715, 759, 667, 763, 707, 662, 671, 680, 1565, 1581, 1563, 1599, 1553, 1589, 1569, 1561, 1599, 1536, 1565, 1559, 1646, 1591, 1644, 1645, 1546, 1579, 1599, 1637, 1618, 2541, 2535, 2471, 2520, 2523, 2523, 2471, 2545, 2493, 2506, 2505, 2485, 2434, 1100, 1098, 1137, 1134, 1147, 1037, 1128, 1106, 1149, 1102, 1118, 1040, 1033, 1146, 1030, 1136, 1113, 1032, 1146, 1144, 1100, 1101, 1117, 1097, 1146, 1039, 1149, 1111, 1100, 1146, 1128, 1110, 1040, 1040, 1030, 1129, 1131, 1106, 1132, 1111, 1127, 1102, 1033, 1038, 1033, 1129, 1142, 1135, 1125, 1102, 1149, 1140, 1102, 1032, 1109, 1040, 1129, 1130, 1133, 1108, 1044, 1037, 1098, 1038, 1099, 1136, 1038, 1141, 1133, 1145, 1114, 1110, 1131, 1118, 1102, 1039, 1077, 1096, 1129, 1141, 1147, 1077, 3109, 3148, 3170, 3116, 3164, 3143, 3191, 3139, 3166, 3160, 3190, 3112, 3103, 2436, 2460, 2502, 2510, 2456, 2495, 2478, 2517, 2448, 2468, 2471, 2499, 2548, 661, 656, 660, 677, 692, 700, 695, 646, 732, 692, 681, 729, 750, 817, 846, 846, 779, 808, 841, 811, 784, 821, 829, 833, 833, 886, 2886, 2882, 2911, 2933, 2906, 2876, 2903, 2902, 2887, 2943, 2928, 2862, 2841, 760, 719, 726, 751, 706, 726, 707, 717, 759, 648, 729, 754, 643, 748, 746, 643, 728, 731, 755, 650, 749, 717, 661, 650, 749, 713, 760, 661, 661, 717, 647, 647, 688, 854, 859, 877, 771, 838, 869, 846, 882, 865, 869, 839, 777, 830, 731, 761, 762, 717, 682, 756, 713, 684, 740, 709, 758, 713, 686, 756, 709, 757, 735, 722, 690, 744, 766, 746, 755, 760, 731, 744, 746, 711, 681, 749, 712, 672, 663, 3037, 3033, 3039, 3036, 3027, 3052, 2953, 3033, 3017, 3011, 3066, 2950, 2993, 1441, 1496, 1440, 1488, 1457, 1469, 1446, 1410, 1425, 1470, 1489, 1459, 1471, 1451, 1421, 1466, 1452, 1502, 1502, 1408, 1459, 1464, 1447, 1468, 1443, 1455, 1489, 1446, 1434, 1500, 1410, 1492, 1507, 1331, 1325, 1382, 1284, 1305, 1337, 1317, 1308, 1336, 1312, 1294, 1386, 1373, 644, 650, 676, 691, 647, 680, 642, 642, 708, 670, 704, 643, 669, 690, 699, 674, 681, 666, 641, 670, 666, 679, 650, 640, 643, 734, 723, 726, 737, 2680, 2626, 2620, 2677, 2618, 2660, 2665, 2627, 2658, 2684, 2634, 2610, 2565, 2524, 2532, 2465, 2555, 2549, 2523, 2517, 2478, 2479, 2516, 2522, 2557, 2541, 2526, 2513, 2520, 2532, 2553, 2533, 2478, 2523, 2500, 2544, 2474, 2461, 1163, 1214, 1193, 1165, 1171, 1254, 1178, 1165, 1201, 1178, 1200, 1250, 1237, 2851, 2855, 2845, 2931, 2940, 2831, 2841, 2854, 2845, 2941, 2855, 2841, 2832, 2872, 2842, 2861, 2835, 2816, 2866, 2930, 2876, 2853, 2943, 2848, 2853, 2863, 2873, 2917, 2879, 2818, 2879, 2874, 2850, 2877, 2935, 2935, 2880, 1346, 1297, 1284, 1317, 1297, 1281, 1326, 1339, 1333, 1298, 1281, 1355, 1404};
        
        // 第3步: 三层解密流程
        // 解密第一部分: 从索引0开始，密钥通过 C0382.f259 ^ 517 计算，种子1574
        // 解密第二部分: 从索引29开始，密钥通过 C0014.f10 ^ (-133) 计算，种子1069  
        // 最终合并: 将两部分合并后再解密，得到明文字符串
        f30498oOoOoOoOoOoOoO0o = oOoOoOo0oOo0o0oO.oOoOoOoOoOoOoO0o(C0487.m1041(f416short, 0, C0382.f259 ^ 517, 1574), C0198.m424(f416short, 29, C0014.f10 ^ (-133), 1069));
    }

    /**
     * 构造函数 - 调试和测试用
     * 
     * 原始代码使用了控制流混淆（XOR + Switch），已还原为清晰逻辑
     * 
     * 功能说明:
     * - 这是一个调试/测试用的构造函数
     * - 当调试标志 ≤ 0 时，打印解密后的测试值
     * - 用于验证字符串解密机制是否正常工作
     * 
     * 原始混淆逻辑分析:
     * - 初始值 i = 1616
     * - i ^= 1633 → i = 49
     * - case 49: i = (debugFlag <= 0) ? 1709 : 1678
     * - 如果 debugFlag ≤ 0: i = 1709 → i ^= 1633 = 204 → 打印
     * - 如果 debugFlag > 0: i = 1678 → i ^= 1633 = 239 → 返回
     */
    public oOoOoOoOoOoOoO0o() {
        // 获取调试标志（可能来自配置或系统属性）
        int debugFlag = C0416.m855();
        
        // 还原后的清晰逻辑：
        // 只有在调试模式下（debugFlag ≤ 0）才打印测试信息
        if (debugFlag <= 0) {
            // 解密测试字符串 "mtjbxvSx07dgtwyleUm" 并打印其值
            // 这是用来验证解密机制是否正常工作的
            int decryptedValue = C0553.m1192("mtjbxvSx07dgtwyleUm");
            System.out.println(Integer.valueOf(decryptedValue));
        }
        // else: 非调试模式，直接返回，不做任何操作
    }

    /**
     * Native方法 #3: Root检测绕过
     * 
     * JNI符号: Java_oOoOoO0o0oOoOoO0_oOoOoOoOoOoOoO0o_OoOo0oO0o0o0oOo0
     * SO实现: libnmmp.so → vmInterpret → libnmmvm.so
     * 
     * 功能: 绕过Root检测，Hook以下类:
     * - com.ss.android.ugc.aweme.security.RootChecker.isRooted() → false
     * - com.ss.android.ugc.aweme.security.RootChecker.checkSuBinary() → false
     * - com.ss.android.ugc.aweme.security.RootChecker.checkRootApps() → false
     * - com.ss.android.ugc.aweme.security.RootChecker.checkBuildProp() → false
     * - com.bytedance.security.device.DeviceChecker (相关检测)
     */
    public static native void OoOo0oO0o0o0oOo0(ClassLoader classLoader);

    /**
     * Native方法 #4: 高清视频解锁
     * 
     * JNI符号: Java_oOoOoO0o0oOoOoO0_oOoOoOoOoOoOoO0o_OoOoO0O0o0oOoO0O
     * SO实现: libnmmp.so → vmInterpret → libnmmvm.so
     * 
     * 功能: 解锁高清视频权限，Hook以下类:
     * - com.ss.android.ugc.aweme.video.VideoQualityManager.canPlayHD() → true
     * - com.ss.android.ugc.aweme.video.VideoQualityManager.getMaxQuality() → "1080p"
     * - com.ss.android.ugc.aweme.video.VideoQualityManager.isVipQualityRequired() → false
     * - com.ss.android.ugc.playerkit.videoview.PlayerConfig (播放器配置)
     */
    public static native void OoOoO0O0o0oOoO0O(ClassLoader classLoader);

    /**
     * Native方法 #2: Hook激活
     * 
     * JNI符号: Java_oOoOoO0o0oOoOoO0_oOoOoOoOoOoOoO0o_OoOoO0o0oO0O0O0O
     * SO实现: libnmmp.so → vmInterpret → libnmmvm.so
     * 
     * 功能: 激活所有已配置的Hook
     * - activateVideoHooks() - 激活视频相关Hook
     * - activateVipHooks() - 激活VIP相关Hook
     * - activateAdBlockHooks() - 激活广告拦截Hook
     * - activateSecurityBypassHooks() - 激活安全绕过Hook
     * - setHookActive(true) - 标记Hook已激活
     */
    public static native void OoOoO0o0oO0O0O0O();

    /**
     * Native方法 #5: 广告拦截
     * 
     * JNI符号: Java_oOoOoO0o0oOoOoO0_oOoOoOoOoOoOoO0o_OoOoOo0O0Oo0o0oO
     * SO实现: libnmmp.so → vmInterpret → libnmmvm.so
     * 
     * 功能: 移除所有广告，Hook以下类:
     * - com.ss.android.ugc.aweme.ad.AdManager.showAd() → null
     * - com.ss.android.ugc.aweme.ad.AdManager.loadAd() → null
     * - com.ss.android.ugc.aweme.ad.AdManager.shouldShowAd() → false
     * - com.bytedance.ad.sdk.AdLoader.requestAd() → null
     */
    public static native void OoOoOo0O0Oo0o0oO(ClassLoader classLoader);

    /**
     * Native方法 #6: 数据获取增强
     * 
     * JNI符号: Java_oOoOoO0o0oOoOoO0_oOoOoOoOoOoOoO0o_OoOoOo0O0o0oO0o0
     * SO实现: libnmmp.so → vmInterpret → libnmmvm.so
     * 
     * 功能: 增强数据获取能力（获取隐藏的用户/视频信息），Hook以下类:
     * - com.ss.android.ugc.aweme.profile.UserProfileManager.canViewProfile() → true
     * - com.ss.android.ugc.aweme.feed.model.Aweme.getVideoUrl() - 增强为高清URL
     * - com.ss.android.ugc.aweme.profile.model.User.isPrivateAccount() → false
     */
    public static native void OoOoOo0O0o0oO0o0(ClassLoader classLoader);

    /**
     * Native方法 #7: 设备信息伪造
     * 
     * JNI符号: Java_oOoOoO0o0oOoOoO0_oOoOoOoOoOoOoO0o_oOo0oO0o0O0O0Oo0
     * SO实现: libnmmp.so → vmInterpret → libnmmvm.so
     * 
     * 功能: 伪造设备信息，绕过设备限制，Hook以下类:
     * - com.ss.android.deviceregister.DeviceRegisterManager.getDeviceId() - 伪造设备ID
     * - android.telephony.TelephonyManager.getDeviceId() - 伪造IMEI
     * - android.provider.Settings.Secure.getString() - 伪造Android ID
     * - android.net.wifi.WifiInfo.getMacAddress() - 伪造MAC地址
     * - com.ss.android.ugc.aweme.device.DeviceUtils (设备工具类)
     */
    public static native void oOo0oO0o0O0O0Oo0(ClassLoader classLoader);

    /**
     * Native方法 #8: 广告请求拦截
     * 
     * JNI符号: Java_oOoOoO0o0oOoOoO0_oOoOoOoOoOoOoO0o_oOo0oOo0Oo0oO0Oo
     * SO实现: libnmmp.so → vmInterpret → libnmmvm.so
     * 
     * 功能: 在网络层拦截广告请求，Hook以下类:
     * - okhttp3.RealCall.execute() - 拦截包含/ad/, /commercial/, /promote/的URL
     * - com.ss.android.ugc.aweme.commercialize.api.CommercializeApi.getAdList() → emptyList
     * - com.bytedance.retrofit2.client.Request (网络请求拦截)
     */
    public static native void oOo0oOo0Oo0oO0Oo();

    /**
     * Native方法 #9: 视频下载（去水印）
     * 
     * JNI符号: Java_oOoOoO0o0oOoOoO0_oOoOoOoOoOoOoO0o_oOoO0OoO0oOo0oOo
     * SO实现: libnmmp.so → vmInterpret → libnmmvm.so
     * 
     * 功能: Hook视频下载流程，移除水印，Hook以下类:
     * - com.ss.android.ugc.aweme.shortvideo.model.Video.getPlayAddr() - 替换为无水印URL
     * - com.ss.android.ugc.aweme.share.ShareService.downloadVideo() - 设置hasWatermark=false
     * - com.ss.android.ugc.aweme.common.WatermarkConfig.isWatermarkEnabled() → false
     */
    public static native void oOoO0OoO0oOo0oOo(ClassLoader classLoader);

    /**
     * Native方法 #10: VIP状态伪造
     * 
     * JNI符号: Java_oOoOoO0o0oOoOoO0_oOoOoOoOoOoOoO0o_oOoO0o0oOo0oO0Oo
     * SO实现: libnmmp.so → vmInterpret → libnmmvm.so
     * 
     * 功能: 伪造VIP状态，Hook以下类:
     * - com.ss.android.ugc.aweme.account.VipManager.isVip() → true
     * - com.ss.android.ugc.aweme.account.VipManager.getVipLevel() → 10 (最高等级)
     * - com.ss.android.ugc.aweme.account.VipManager.hasVipPrivilege() → true
     * - com.ss.android.ugc.aweme.account.model.User.getVipExpireTime() → MAX_VALUE
     */
    public static native void oOoO0o0oOo0oO0Oo();

    /**
     * Native方法 #1: Hook框架初始化
     * 
     * JNI符号: Java_oOoOoO0o0oOoOoO0_oOoOoOoOoOoOoO0o_oOoOo0O0Oo0o0OoO
     * SO实现: libnmmp.so (通过classesInit0注册) → vmInterpret → libnmmvm.so
     * 
     * 功能: 初始化Xposed Hook框架，Hook以下类:
     * - de.robv.android.xposed.XposedBridge (Xposed主桥)
     * - de.robv.android.xposed.XposedHelpers (Xposed辅助类)
     * - com.pop.d.base.xd.CustomXposedBridge.init() - Hook初始化方法
     * 
     * 操作步骤:
     * 1. 初始化Hook环境
     * 2. 设置ClassLoader
     * 3. 初始化反射缓存
     */
    public static native void oOoOo0O0Oo0o0OoO(ClassLoader classLoader);

    /**
     * Native方法 #11: 网络请求Hook
     * 
     * JNI符号: Java_oOoOoO0o0oOoOoO0_oOoOoOoOoOoOoO0o_oOoOoO0oOoO0OoOo
     * SO实现: libnmmp.so → vmInterpret → libnmmvm.so
     * 
     * 功能: Hook网络请求，修改参数和响应，Hook以下类:
     * - okhttp3.OkHttpClient$Builder.build() - 添加自定义拦截器
     * - com.ss.android.ugc.aweme.net.ApiResponse.getData() - 修改响应数据
     * - okhttp3.Request$Builder.build() - 修改请求头（如添加VIP标识）
     * - com.ss.android.ugc.aweme.net.NetworkClient (网络客户端)
     */
    public static native void oOoOoO0oOoO0OoOo(ClassLoader classLoader);

    /**
     * Native方法 #12: VIP功能解锁
     * 
     * JNI符号: Java_oOoOoO0o0oOoOoO0_oOoOoOoOoOoOoO0o_oOoOoOo0O0O0oO0o
     * SO实现: libnmmp.so → vmInterpret → libnmmvm.so
     * 
     * 功能: 解锁所有VIP专属功能，Hook以下类:
     * - com.ss.android.ugc.aweme.sticker.StickerManager.canUseVipSticker() → true
     * - com.ss.android.ugc.aweme.music.MusicManager.canUseVipMusic() → true
     * - com.ss.android.ugc.aweme.creative.CreativeToolsManager.canUseVipTemplate() → true
     * - com.ss.android.ugc.aweme.download.DownloadLimitManager.canDownload() → true
     * - com.ss.android.ugc.aweme.player.PlayerLimitManager.getMaxWatchTime() → MAX_VALUE
     * - com.ss.android.ugc.aweme.premium.PremiumFeatureManager (高级功能管理)
     */
    public static native void oOoOoOo0O0O0oO0o(ClassLoader classLoader);

    /**
     * Native方法 #13: 隐藏内容访问
     * 
     * JNI符号: Java_oOoOoO0o0oOoOoO0_oOoOoOoOoOoOoO0o_oOoOoOo0oO0oO0o0
     * SO实现: libnmmp.so → vmInterpret → libnmmvm.so
     * 
     * 功能: 访问隐藏/私密的视频和内容，Hook以下类:
     * - com.ss.android.ugc.aweme.feed.FeedVisibilityChecker.isVideoVisible() → true
     * - com.ss.android.ugc.aweme.feed.model.Aweme.isPrivate() → false
     * - com.ss.android.ugc.aweme.privacy.PrivacyManager.canViewFriendOnly() → true
     * - com.ss.android.ugc.aweme.feed.model.Aweme.isRegionRestricted() → false
     */
    public static native void oOoOoOo0oO0oO0o0(ClassLoader classLoader);

    /**
     * Native方法 #14: 风控绕过
     * 
     * JNI符号: Java_oOoOoO0o0oOoOoO0_oOoOoOoOoOoOoO0o_oOoOoOo0oOo0o0oO
     * SO实现: libnmmp.so → vmInterpret → libnmmvm.so
     * 
     * 功能: 绕过风控系统检测，Hook以下类:
     * - com.ss.android.ugc.aweme.riskcontrol.RiskManager.evaluateRisk() → 0 (安全)
     * - com.ss.android.ugc.aweme.riskcontrol.RiskManager.isRiskyBehavior() → false
     * - com.ss.android.ugc.aweme.riskcontrol.CaptchaManager.needCaptcha() → false
     * - com.bytedance.ttnet.riskcontrol.DeviceFingerprint.isAbnormal() → false
     * - com.ss.android.ugc.aweme.riskcontrol.RateLimiter.isRateLimited() → false
     * - com.bytedance.ttnet.riskcontrol.RiskControlManager (风控管理器)
     */
    public static native void oOoOoOo0oOo0o0oO(ClassLoader classLoader);

    /**
     * Native方法 #15: 反作弊绕过
     * 
     * JNI符号: Java_oOoOoO0o0oOoOoO0_oOoOoOoOoOoOoO0o_oOoOoOoOoOoOoO0o
     * SO实现: libnmmp.so → vmInterpret → libnmmvm.so
     * 
     * 功能: 绕过反作弊检测，Hook以下类:
     * - com.ss.android.ugc.aweme.security.SecurityChecker.isXposedInstalled() → false
     * - com.ss.android.ugc.aweme.security.SecurityChecker.detectHookFramework() → false
     * - com.ss.android.ugc.aweme.anticheat.MemoryChecker.checkMemoryAbnormal() → false
     * - com.ss.android.ugc.aweme.security.SecurityChecker.detectSuspiciousModules() → emptyList
     * - com.ss.android.ugc.aweme.security.SignatureChecker.verifySignature() → true
     * - com.ss.android.ugc.aweme.security.IntegrityChecker.checkIntegrity() → true
     * - com.ss.android.ugc.aweme.anticheat.AntiCheatManager (反作弊管理器)
     */
    public static native void oOoOoOoOoOoOoO0o(ClassLoader classLoader);
}
