<template>
  <div id="app">
    <nav class="navbar navbar-expand navbar-dark bg-dark">
      <div class="navbar-brand">vue-login</div>
      <div class="navbar-nav mr-auto">
        <li class="nav-item">
          <a href="/" class="nav-link">
            <font-awesome-icon icon="home" /> Home
          </a>
        </li>
      </div>
      <div class="navbar-nav ml-auto" v-if="!currentUser">
        <li class="nav-item">
          <a href="/register" class="nav-link">
            <font-awesome-icon icon="user-plus" /> Sign Up
          </a>
        </li>
        <li class="nav-item">
          <a href="/login" class="nav-link">
            <font-awesome-icon icon="sign-in-alt" /> Login
          </a>
        </li>
      </div>

      <div class="navbar-nav ml-auto" v-if="currentUser">
        <li class="nav-item">
          <a href="/profile" class="nav-link">
            <font-awesome-icon icon="user" />
            {{currentUser.username}}
          </a>
        </li>
        <li class="nav-item">
          <a href class="nav-link" @click="logOut">
            <font-awesome-icon icon="sign-out-alt" /> LogOut
          </a>
        </li>
      </div>
    </nav>
    <div class="container">
      <router-view />
    </div>
  </div>
</template>

<script>
export default {
  computed: {
    currentUser() {
      return this.$store.state.auth.user
    },
    showAdminBoard() {
      if (this.currentUser) {
        // return this.currentUser.roles.includes('ROLE_ADMIN')
      }

      return false
    },
    showModeratorBoard() {
      if (this.currentUser) {
        // return this.currentUser.roles.includes('ROLE_MODERATOR')
      }

      return false
    }
  },
  methods: {
    logOut() {
      this.$store.dispatch('auth/logout')
      this.$router.push('/')
    }
  }
}
</script>
