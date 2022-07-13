import { createRouter, createWebHistory, RouteRecordRaw } from "vue-router";
import { useAuthStore } from "@/store/useAuth";
const dynamicRoutes = [];

const staticRoutes = [
  {
    path: "/auth",
    redirect: "/",
    component: () =>
      import(
        /* webpackChunkName: "auth_layout" */ "@/components/layouts/Auth.vue"
      ),
    children: [
      {
        path: "sign-in",
        name: "sign-in",
        meta: {
          auth: true,
        },
        component: () =>
          import(/* webpackChunkName: "sign_in" */ "@/views/auth/SignIn.vue"),
      },
      {
        path: "sign-up",
        name: "sign-up",
        meta: {
          auth: true,
        },
        component: () =>
          import(
            /* webpackChunkName: "sign_up" */
            "@/views/auth/SignUp.vue"
          ),
      },
      {
        path: "password-reset",
        name: "password-reset",
        meta: {
          auth: true,
        },
        component: () =>
          import(
            /* webpackChunkName: "password_reset" */ "@/views/auth/ResetPassword.vue"
          ),
      },
      {
        path: "email-reset-password",
        name: "email-reset-password",
        meta: {
          auth: true,
        },
        component: () =>
          import(
            /* webpackChunkName: "password_reset" */ "@/views/auth/EmailResetPassword.vue"
          ),
      },
      {
        path: "msg-reset-password",
        name: "msg-reset-password",
        meta: {
          auth: true,
        },
        component: () =>
          import(
            /* webpackChunkName: "password_reset" */ "@/views/auth/MsgResetPassword.vue"
          ),
      },
    ],
  },
  {
    path: "",
    meta: {
      requiresAuth: true,
    },
    component: () =>
      import(
        /* webpackChunkName: "layout" */ "@/components/layouts/mainLayout/Layout.vue"
      ),
    children: [
      {
        name: "home",
        path: "/",
        meta: {
          requiresAuth: true,
        },
        component: () =>
          import(/* webpackChunkName: "HomePage" */ "@/views/Home.vue"),
      },
    ],
  },
  {
    // the 404 route, when none of the above matches
    path: "/404",
    name: "404",
    component: () =>
      import(/* webpackChunkName: "error_404" */ "@/views/errors/Error404.vue"),
  },
  {
    path: "/:pathMatch(.*)*",
    redirect: "/404",
  },
  {
    path: "/users",
    meta: {
      requiresAuth: true,
    },
    redirect: "/",
    component: () =>
      import(
        /* webpackChunkName: "layout" */ "@/components/layouts/mainLayout/Layout.vue"
      ),
    children: [
      {
        path: "",
        name: "list-user",
        component: () =>
          import(
            /* webpackChunkName: "list-user" */ "@/views/main/user/UserList.vue"
          ),
      },
      {
        path: "edit/:id",
        name: "edit-user",
        component: () =>
          import(
            /* webpackChunkName: "edit-user" */ "@/views/main/user/UserEdit.vue"
          ),
      },
      {
        path: ":id",
        name: "detail-user",
        component: () =>
          import(
            /* webpackChunkName: "detail-user" */ "@/views/main/user/UserDetail.vue"
          ),
      },
    ],
  },
];

const routes: Array<RouteRecordRaw> = [...staticRoutes, ...dynamicRoutes];

const router = createRouter({
  history: createWebHistory(),
  routes,
});

router.beforeEach(async (to, from, next) => {
  const requiresAuth = to.matched.some((record) => record.meta.requiresAuth);
  const authRoute = to.matched.some((record) => record.meta.auth);
  const store = useAuthStore();
  await store.getCurrent();

  if (store.isLoggedIn && authRoute && !to.fullPath.includes("type=recovery")) {
    next({ name: "home" });
    return;
  }

  if (requiresAuth && !store.isLoggedIn) {
    next({ name: "sign-in" });
    return;
  }
  next();
  return;
});

export default router;
