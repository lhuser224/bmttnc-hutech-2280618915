so_gio_lam = float(input("Nhập số giờ làm mỗi tuần : "))
luong_gio = float(input("Nhập số thù lao trên mỗi giờ làm tiêu chuẩn : "))
gio_tc = 44 # tiêu chuẩn
gio_vc = max(0, so_gio_lam - gio_tc) # vượt chuẩn
thuc_linh= gio_tc * luong_gio + gio_vc*luong_gio * 1.5
print(f"Số tiền thực lĩnh của nhân viên: {thuc_linh}")