<template>
  <KTLoader v-if="loaderEnabled" :logo="loaderLogo"></KTLoader>

  <!-- begin:: Body -->
  <div class="page d-flex flex-row flex-column-fluid">
    <!-- begin:: Aside Left -->
    <KTAside v-if="asideEnabled" :lightLogo="themeLightLogo"></KTAside>
    <!-- end:: Aside Left -->

    <div id="kt_wrapper" class="d-flex flex-column flex-row-fluid wrapper">
      <KTHeader :title="pageTitle">
        <div
          class="d-none d-lg-flex align-items-stretch flex-shrink-0 logo-nav"
        >
          <Logo></Logo>
        </div>
        <!--begin::Navbar-->
        <div class="d-flex align-items-stretch" id="kt_header_menu_nav">
          <Menu></Menu>
        </div>
        <!--end::Navbar-->

        <!--begin::Topbar-->
        <div class="d-flex align-items-stretch flex-shrink-0">
          <Topbar></Topbar>
        </div>
      </KTHeader>
      <!-- begin:: Content -->
      <div
        id="kt_content"
        class="content pt-4 d-flex flex-column flex-column-fluid container-fluid"
      >
        <!-- begin:: Content Head -->
        <KTToolbar
          v-if="subheaderDisplay"
          :breadcrumbs="pageBreadcrumbPath"
          :title="pageTitle"
        />
        <!-- end:: Content Head -->

        <!-- begin:: Content Body -->
        <div class="post d-flex flex-column-fluid">
          <div
            id="kt_content_container"
            :class="{
              'container-fluid': contentWidthFluid,
            }"
            class="w-100 mx-4"
          >
            <router-view />
          </div>
        </div>
        <!-- end:: Content Body -->
      </div>
      <!-- end:: Content -->
      <KTFooter></KTFooter>
    </div>
  </div>
  <!-- <ModalLoader></ModalLoader> -->
  <!-- end:: Body -->
  <KTScrollTop></KTScrollTop>
</template>

<script lang="ts">
import { defineComponent, computed, onMounted, watch } from "vue";

import { useRoute, useRouter } from "vue-router";
import KTAside from "@/components/layouts/mainLayout/aside/Aside.vue";
import KTHeader from "@/components/layouts/mainLayout/header/HeaderDevFactory.vue";
import KTFooter from "@/components/layouts/mainLayout/footer/FooterDevFactory.vue";
import HtmlClass from "@/core/services/LayoutService";
import KTToolbar from "@/components/layouts/mainLayout/toolbar/Toolbar.vue";
import KTScrollTop from "@/components/layouts/mainLayout/extras/ScrollTop.vue";

import KTLoader from "@/components/shared/Loader.vue";

import { MenuComponent, DrawerComponent } from "@/assets/ts/components/index";
import {
  loaderEnabled,
  contentWidthFluid,
  loaderLogo,
  asideEnabled,
  subheaderDisplay,
  themeLightLogo,
} from "@/core/helpers/config";
// import ModalLoader from "./ModalLoader.vue";
import Logo from "./header/Logo.vue";
import Menu from "./header/Menu.vue";
import Topbar from "./header/Topbar.vue";
import { useBodyStore } from "@/store/useBodyModule";
import { useConfigStore } from "@/store/useConfig";
import { storeToRefs } from "pinia";
import { useAuthStore } from "@/store/useAuth";

export default defineComponent({
  name: "Layout",
  components: {
    KTAside,
    KTHeader,
    KTFooter,
    KTToolbar,
    KTScrollTop,
    KTLoader,
    // ModalLoader,
    Logo,
    Menu,
    Topbar,
  },
  setup() {
    const { addBodyClassName, removeBodyClassName } = useBodyStore();
    const route = useRoute();

    // show page loading
    addBodyClassName("page-loading");
    // store.dispatch(Actions.FETCH_USER_TOKEN);

    // initialize html element classes
    HtmlClass.init();

    const tokenUser = computed(() => {
      // return store.getters.userToken;
      return "token";
    });

    const { pageBreadcrumbPath, pageTitle } = storeToRefs(useConfigStore());
    const user = useAuthStore();
    onMounted(() => {
      //check if current user is authenticated
      //user.getCurrent();

      DrawerComponent.bootstrap();
      DrawerComponent.updateAll();

      // Simulate the delay page loading
      setTimeout(() => {
        // Remove page loader after some time
        removeBodyClassName("page-loading");
      }, 200);
    });

    watch(
      () => route.path,
      () => {
        MenuComponent.hideDropdowns(undefined);

        DrawerComponent.hideAll();

        // check if current user is authenticated
        //user.getCurrent();
      }
    );

    return {
      loaderEnabled,
      contentWidthFluid,
      loaderLogo,
      asideEnabled,
      subheaderDisplay,
      pageTitle,
      pageBreadcrumbPath,
      themeLightLogo,
    };
  },
});
</script>

<style lang="scss">
@media (min-width: 992px) {
  .wrapper {
    padding-left: 0px !important;
  }
}
</style>
