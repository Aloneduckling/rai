const NavbarButton: React.FC<{
    isLoggedIn: boolean
}> = ({ isLoggedIn }) => {
  return (
    <button className="flex self-center text-xl font-bold border-[3px] border-black bg-base rounded-2xl py-1 px-6 hover:bg-base-200 transition-all">
        { isLoggedIn? "Logout" : "login"}
    </button>
  )
}

export default NavbarButton