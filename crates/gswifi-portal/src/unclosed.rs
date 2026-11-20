//! Profiles whose derivation is not closed. Their constructors always fail
//! with a message naming what is missing (clean-room rule 5, gaps.md
//! "湖北 / 云南 网页 Portal" and convention 3): shipping a guessed pipeline
//! would lock accounts and claim support that does not exist.
//!
//! The types exist so the CLI registry can name every profile; they hold
//! [`Infallible`], so no value can ever be built and the [`Driver`] methods
//! are statically unreachable.

use std::convert::Infallible;
use std::time::Instant;

use gswifi_core::{Action, AuthState, Credentials, Driver, DriverInfo, Env, NetInfo, Requirements};

use crate::driver::PortalOptions;

/// Why `portal-hubei-new-mac` cannot run (cleanroom/08 §2, §5).
pub const HUBEI_NEW_MAC_MISSING: &str = "湖北新Mac（hubei_mac_web_new）尚未闭合，不能使用：密码管线的 \"After RC4\" 新增阶段、\
CheckVersion/NoticeInfo 分支与 %Y%m%d%H%M%S 时间格式的完整变换都没有固件向量（cleanroom/08 §2、§5；docs/gaps.md「湖北 / 云南 网页 Portal」）。\
旧Mac的派生不能替代它。闭合方法：用旧Mac的 QEMU harness 定位新二进制的对应函数并导出金向量";

/// Why `portal-hubei-android` cannot run (cleanroom/08 §3, §5).
pub const HUBEI_ANDROID_MISSING: &str = "湖北Android（hubei_android_web）尚未闭合，不能使用：AidcAuthAttr1/3/4/5/6/7/8/15/22/23 \
各自的取值来源与编码顺序未知，Password 派生也未执行验证（cleanroom/08 §3、§5；docs/gaps.md「湖北 / 云南 网页 Portal」）。\
闭合方法：URL 编码前后的请求样例加逐字段追踪";

/// Why `portal-yunnan-web` cannot run (cleanroom/07 §4, §5, §7).
pub const YUNNAN_WEB_MISSING: &str = "云南Web（adial_yn_web）尚未闭合，不能使用：两种登录表单（带/不带 !^B6EA）的选择条件与 \
Password 是否派生均未定位，心跳 URL 与间隔来自未解码的 NkConfig（cleanroom/07 §4、§5、§7；docs/gaps.md「湖北 / 云南 网页 Portal」）。\
闭合方法：派生函数输入输出追踪、NkConfig 解码金样本、一次成功会话抓包";

/// Why `portal-yunnan-pppoe` cannot run (cleanroom/07 §3, §7).
pub const YUNNAN_PPPOE_MISSING: &str = "云南PPPoE（adial_yn_pppoe）尚未闭合，不能使用：只知道账号前缀 !^B6EA，\
其后的派生字段、用户名变换与 @xyw 后缀的条件均未核实（cleanroom/07 §3、§7；docs/gaps.md「湖北 / 云南 网页 Portal」）。\
闭合方法：switch_pppoe 调用前的逐派生函数输入输出追踪";

macro_rules! unclosed_driver {
    ($(#[$doc:meta])* $name:ident, $missing:ident) => {
        $(#[$doc])*
        pub struct $name {
            never: Infallible,
        }

        impl $name {
            /// Always fails: the profile is not closed.
            pub fn new(_env: Env, _credentials: Credentials, _options: PortalOptions) -> Result<Self, String> {
                Err($missing.to_string())
            }
        }

        impl Driver for $name {
            fn info(&self) -> &'static DriverInfo {
                match self.never {}
            }
            fn requirements(&self) -> Requirements {
                match self.never {}
            }
            fn start(&mut self, _now: Instant) -> Vec<Action> {
                match self.never {}
            }
            fn on_timer(&mut self, _now: Instant) -> Vec<Action> {
                match self.never {}
            }
            fn on_net_change(&mut self, _net: NetInfo, _now: Instant) -> Vec<Action> {
                match self.never {}
            }
            fn next_deadline(&self) -> Option<Instant> {
                match self.never {}
            }
            fn logoff(&mut self, _now: Instant) -> Vec<Action> {
                match self.never {}
            }
            fn state(&self) -> AuthState {
                match self.never {}
            }
        }
    };
}

unclosed_driver!(
    /// `portal-hubei-new-mac`: refused, see [`HUBEI_NEW_MAC_MISSING`].
    HubeiNewMacDriver,
    HUBEI_NEW_MAC_MISSING
);
unclosed_driver!(
    /// `portal-hubei-android`: refused, see [`HUBEI_ANDROID_MISSING`].
    HubeiAndroidDriver,
    HUBEI_ANDROID_MISSING
);
unclosed_driver!(
    /// `portal-yunnan-web`: refused, see [`YUNNAN_WEB_MISSING`].
    YunnanWebDriver,
    YUNNAN_WEB_MISSING
);
unclosed_driver!(
    /// `portal-yunnan-pppoe`: refused, see [`YUNNAN_PPPOE_MISSING`].
    YunnanPppoeDriver,
    YUNNAN_PPPOE_MISSING
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unclosed_profiles_refuse_with_a_reason() {
        let build = || (Env::default(), Credentials::new("u", "p"), PortalOptions::default());
        let errors = [
            HubeiNewMacDriver::new(build().0, build().1, build().2).err().unwrap(),
            HubeiAndroidDriver::new(build().0, build().1, build().2).err().unwrap(),
            YunnanWebDriver::new(build().0, build().1, build().2).err().unwrap(),
            YunnanPppoeDriver::new(build().0, build().1, build().2).err().unwrap(),
        ];
        for e in &errors {
            assert!(e.contains("gaps.md") && e.contains("cleanroom/0"), "{}", e);
            assert!(e.contains("不能使用"));
        }
        assert!(errors[0].contains("After RC4"));
        assert!(errors[1].contains("AidcAuthAttr"));
        assert!(errors[2].contains("NkConfig"));
        assert!(errors[3].contains("@xyw"));
    }
}
