import React from 'react';
import { Routes, Route, } from 'react-router-dom';
import './App.css';

import Register from './pages/Register';
import Login from './pages/Login';
import Verify from './pages/Verify';

function App() {
	return (
  <Routes>
    <Route index element={<Login />} />
    <Route path="/register" element={<Register />} />
    <Route path="/login" element={<Login />} />
		<Route path="/verify" element={<Verify />} />
	</Routes>
	);
}

export default App;