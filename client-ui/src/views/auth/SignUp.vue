<template>
  <div
    class="d-flex align-items-center justify-content-center"
    style="height: 100vh"
  >
    <!--Illustration-->
    <div class="d-flex bg-login">
      <div
        class="bgi-no-repeat bgi-position-x-center bgi-size bgi-position-center min-h-200px min-h-xl-600px mb-xl-10 test3 square2"
        style="
          background-image: url('/svg/authentication/login-ellipse-icon.svg');
          position: absolute;
          top: -14%;
          left: -14%;
          width: 42%;
          transform: rotate(180deg);
          z-index: -1;
        "
      />
      <div
        class="bgi-no-repeat bgi-position-x-center bgi-size bgi-position-center min-h-200px min-h-xl-600px mb-xl-10 test3 square2"
        style="
          background-image: url('/svg/authentication/admin-registre-icon.svg');
          position: absolute;
          top: 0%;
          left: 0%;
          width: 22%;
          z-index: -1;
        "
      />
      <div
        class="bgi-no-repeat bgi-position-x-center bgi-size bgi-position-center min-h-200px min-h-xl-600px mb-xl-10 test3 square2"
        style="
          background-image: url('/svg/authentication/login-ellipse-icon.svg');
          position: absolute;
          bottom: 0%;
          right: 0%;
          width: 45%;
          z-index: -1;
        "
      />
      <div
        class="bgi-no-repeat bgi-position-x-center bgi-size bgi-position-center min-h-200px min-h-xl-500px mb-xl-10 test3 w-25"
        style="
          background-image: url('/svg/authentication/member-registre-icon.svg');
          z-index: 1;
          position: absolute;
          bottom: 0;
          right: 0%;
        "
      ></div>
    </div>
    <!-- end Illustration-->
    <div class="w-lg-500px mb-10 mb-lg-3 mx-auto d-flex flex-column">
      <img alt="Logo" src="/svg/logos/logo.svg" class="h-60px mb-lg-20" />
      <el-card class="card">
        <div class="card-body p-lg-9">
          <h1 class="d-flex justify-content-center fw-bolder">
            {{ t("signUpInterface.title") }}
          </h1>
          <div class="d-flex justify-content-center">
            <h4 class="text-gray-400 fw-bold">
              {{ t("alreadyHaveAnAccount") }}?
              <router-link :to="{ name: 'sign-in' }" class="fw-bolder">
                {{ t("signIn") }}
              </router-link>
            </h4>
          </div>
          <div class="mt-lg-10">
            <label class="form-label fw-bolder text-gray-900 fs-6">{{
              t("email")
            }}</label>
            <el-input size="large" type="email" v-model="email" />
          </div>

          <div class="mt-lg-8">
            <label class="form-label fw-bolder text-gray-900 fs-6">{{
              t("password")
            }}</label>
            <el-input type="password" size="large" v-model="password" />
          </div>

          <div class="mt-lg-8">
            <label class="form-label fw-bolder text-gray-900 fs-6">{{
              t("role")
            }}</label>
            <el-select
              class="w-100"
              v-model="role"
              size="large"
              placeholder="Choisir role"
              style="width: auto"
            >
              <el-option
                v-for="item in roles"
                :key="item.value"
                :label="item.label"
                :value="item.value"
                :disabled="item.disabled"
              />
            </el-select>
          </div>

          <div class="mt-lg-10 d-grid">
            <el-button
              @click="signUp()"
              type="primary"
              size="large"
              class="mt-2"
              >{{ t("signUp") }}</el-button
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
import { defineComponent, ref } from "vue";
let failMessage: string | null;
const roles = [
  {
    value: "user",
    label: "User",
  },
  {
    value: "admin",
    label: "Admin",
    disabled: true,
  },
];
export default defineComponent({
  name: "sign-up",
  setup() {
    failMessage = t("messages.signUpFailed");
    const authStore = useAuthStore();
    const password = ref("");
    const email = ref("");
    const role = ref("user");

    const signUp = async () => {
      try {
        await authStore.signUp(email.value, password.value, role.value);
      } catch (error) {
        Components.ElMessage.error(failMessage);
        console.log(error);
      }
    };
    return {
      t,
      email,
      password,
      role,
      roles,
      authStore,
      signUp,
    };
  },
});
</script>
