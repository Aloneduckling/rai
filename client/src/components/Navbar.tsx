import raiLogo from '../assets/rai.svg';
import NavbarButton from './NavbarButton';


const Navbar = () => {
  return (
    <nav className='flex justify-between'>
        <img src={raiLogo} alt="rai-logo" />
        <NavbarButton isLoggedIn={false}/>
    </nav>
  )
}

export default Navbar