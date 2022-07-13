<template>
  <div
    class="d-flex align-items-center justify-content-center"
    style="height: 100vh"
  >
    <!--Illustration-->
    <div class="d-flex bg-login">
      <div
        class="bgi-no-repeat bgi-position-x-center bgi-size bgi-position-center min-h-200px min-h-xl-500px mb-xl-10 test3 w-25"
        style="
          background-image: url('/svg/authentication/login-geolocation-icon.svg');
          z-index: 1;
          position: absolute;
          bottom: 0%;
          left: 0%;
        "
      ></div>
      <div
        class="bgi-no-repeat bgi-position-x-center bgi-size bgi-position-center min-h-200px min-h-xl-500px mb-xl-10 test3 w-25"
        style="
          background-image: url('/svg/authentication/login-community-icon.svg');
          position: absolute;
          bottom: 0%;
          right: 0%;
          z-index: -1;
        "
      ></div>
      <div
        class="bgi-no-repeat bgi-position-x-end bgi-size bgi-position-y-bottom min-h-200px min-h-xl-400px mb-xl-10 test4"
        style="
          background-image: url('/svg/authentication/login-polygon-icon.svg');
          position: absolute;
          bottom: 0;
          width: 22%;
          left: 60%;
          z-index: -1;
        "
      ></div>
      <div
        class="bgi-no-repeat bgi-position-x-center bgi-size bgi-position-center min-h-200px min-h-xl-600px mb-xl-10 test3 square2"
        style="
          background-image: url('/svg/authentication/login-ellipse-icon.svg');
          position: absolute;
          bottom: 0%;
          left: 14%;
          width: 45%;
          z-index: -2;
        "
      ></div>
    </div>
    <!-- end Illustration-->
    <div class="w-lg-500px mb-10 mb-lg-3 mx-auto d-flex flex-column">
      <img alt="Logo" src="/svg/logos/logo.svg" class="h-60px mb-lg-20" />
      <el-card class="card">
        <div class="card-body p-lg-9">
          <h1 class="d-flex justify-content-center fw-bolder">
            {{ t("login.title") }}
          </h1>
          <div class="d-flex justify-content-center mt-5">
            <h4 class="text-gray-400 fw-bold">
              {{ t("login.newHere") }}?
              <router-link :to="{ name: 'sign-up' }" class="fw-bolder">{{
                t("login.register")
              }}</router-link>
            </h4>
          </div>
          <div class="mt-lg-10">
            <label class="form-label fw-bolder text-gray-900 fs-6">
              {{ t("email") }}</label
            >
            <el-input size="large" type="email" v-model="email" />
          </div>
          <div class="mt-lg-8">
            <div class="row justify-content-between form-label">
              <div class="col-6 text-start fw-bolder text-gray-900 fs-6">
                {{ t("password") }}
              </div>
              <div class="col-6 text-end">
                <router-link :to="{ name: 'email-reset-password' }"
                  >{{ t("forgotPassword") }} ?</router-link
                >
              </div>
            </div>
            <el-input type="password" size="large" v-model="password" />
          </div>
          <div class="mt-lg-10 d-grid">
            <el-button
              @click="login()"
              type="primary"
              size="large"
              class="btn-lg mt-2"
              >{{ t("signIn") }}</el-button
            >
          </div>
        </div>
      </el-card>
    </div>
  </div>
</template>
<script lang="ts">
import { Components } from "@tekab-dev-team/storybook-devfactory";
import { t } from "@/core/i18n/translate";
import { useAuthStore } from "@/store/useAuth";
import { ref, defineComponent } from "vue";
import { storeToRefs } from "pinia";
let failMessage: string | null;

export default defineComponent({
  name: "sign-in",
  setup() {
    failMessage = t("messages.loginFailed");
    const authStore = useAuthStore();
    const { accessToken } = storeToRefs(useAuthStore());
    const password = ref("");
    const email = ref("");
    const login = async () => {
      try {
        await authStore.login(email.value, password.value);
      } catch (error) {
        Components.ElMessage.error(failMessage);
      }
    };
    return {
      t,
      email,
      password,
      authStore,
      login,
    };
  },
});
</script>
<style lang="scss" scoped>
.el-input {
  background-color: #e9ecef;
}
@media (max-width: 1200px) {
  .bg-login {
    display: none !important;
  }
}
</style>
